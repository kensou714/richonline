#include "lobby.hpp"

#include <algorithm>
#include <bit>
#include <utility>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace richnet {
namespace {
View slot_text(View slot) {
    const auto end = std::find(slot.begin(), slot.end(), std::uint8_t{0});
    if (end == slot.end()) throw CodecError("login_slot_not_terminated");
    return slot.first(static_cast<std::size_t>(end - slot.begin()));
}

std::string decode_username(View bytes, ClientVersion version) {
    if (bytes.empty()) throw CodecError("login_username_empty");
    const bool original = version == ClientVersion::legacy;
#ifdef _WIN32
    const UINT code_page = original ? 936U : 950U;
    const auto* input = reinterpret_cast<const char*>(bytes.data());
    const auto length = static_cast<int>(bytes.size());
    const auto count = MultiByteToWideChar(code_page, MB_ERR_INVALID_CHARS, input, length, nullptr, 0);
    if (count == 0) throw CodecError(original ? "login_username_invalid_gbk" : "login_username_invalid_big5");
    std::wstring wide(static_cast<std::size_t>(count), L'\0');
    if (MultiByteToWideChar(code_page, MB_ERR_INVALID_CHARS, input, length, wide.data(), count) != count)
        throw CodecError(original ? "login_username_gbk_conversion_failed" : "login_username_big5_conversion_failed");
    const auto output_size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), count,
                                               nullptr, 0, nullptr, nullptr);
    if (output_size == 0) throw CodecError("login_username_utf8_conversion_failed");
    std::string output(static_cast<std::size_t>(output_size), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), count, output.data(),
                            output_size, nullptr, nullptr) != output_size)
        throw CodecError("login_username_utf8_conversion_failed");
    return output;
#else
    if (std::any_of(bytes.begin(), bytes.end(), [](std::uint8_t c) { return c >= 128; }))
        throw CodecError(original ? "gbk_conversion_requires_windows" : "big5_conversion_requires_windows");
    return std::string(bytes.begin(), bytes.end());
#endif
}

void validate_handshake(const LobbyOptions& options) {
    if (!options.handshake) throw CodecError("lobby_handshake_not_configured");
    const auto& h = *options.handshake;
    // Bound multiplication to signed32 so both DH participants share ordinary modular arithmetic.
    if (h.modulus < 3 || h.modulus > 46340 || h.generator < 2 || h.generator >= h.modulus ||
        h.private_exponent < 1)
        throw CodecError("lobby_handshake_parameters_outside_supported_subset");
}
}

LobbyHandshake local_lobby_handshake() { return {579, 5, 251, 7}; }

RichLobbySession::RichLobbySession(LobbyOptions options, LobbyCallbacks callbacks, LobbyLogSink log)
    : options_(std::move(options)), callbacks_(std::move(callbacks)), log_(std::move(log)) {}

RichLobbySession::~RichLobbySession() { close(); }

Bytes RichLobbySession::start() try {
    if (state_ != LobbyState::not_started) throw CodecError("lobby_session_already_started");
    validate_handshake(options_);
    const auto& h = *options_.handshake;
    Bytes payload;
    append_le(payload, static_cast<std::uint32_t>(h.generator), 4);
    append_le(payload, static_cast<std::uint32_t>(h.modulus), 4);
    append_le(payload, static_cast<std::uint32_t>(modpow_signed32(h.generator, h.private_exponent, h.modulus)), 4);
    state_ = LobbyState::awaiting_public_key;
    if (log_) log_("lobby_handshake_sent type=" + std::to_string(h.wire_type));
    return encode_frame({h.wire_type, payload}, {Channel::lobby_s2c, std::nullopt, options_.version});
} catch (...) {
    close();
    throw;
}

std::vector<Frame> RichLobbySession::receive(const Frame& frame) {
    if (log_) log_("lobby_received type=" + std::to_string(frame.wire_type) +
                   " payload_bytes=" + std::to_string(frame.payload.size()));
    switch (state_) {
    case LobbyState::awaiting_public_key: {
        if (frame.wire_type != 759 || frame.payload.size() != 4)
            throw CodecError("invalid_lobby_client_public_frame");
        const auto client_public = std::bit_cast<std::int32_t>(read_le(frame.payload));
        const auto& h = *options_.handshake;
        if (client_public <= 0 || client_public >= h.modulus)
            throw CodecError("lobby_client_public_outside_supported_subset");
        key_ = modpow_signed32(client_public, h.private_exponent, h.modulus);
        state_ = LobbyState::awaiting_login;
        return {};
    }
    case LobbyState::awaiting_login: {
        const bool original = options_.version == ClientVersion::legacy;
        if (frame.wire_type != 58 || frame.payload.size() != 144)
            throw CodecError(original ? "invalid_original_login_frame" : "invalid_richonline_login_frame");
        const View payload(frame.payload);
        const auto descriptor = read_le(payload.first(4));
        if (read_le(payload.subspan(4, 4)) != (original ? 132U : 0U) ||
            read_le(payload.subspan(8, 4)) != 0 || (!original && descriptor != 0))
            throw CodecError(original ? "unsupported_original_login_descriptor" : "unsupported_richonline_login_descriptor");
        const LobbyLogin login{decode_username(slot_text(payload.subspan(12, 64)), options_.version),
                               read_le(payload.subspan(140, 4)), descriptor};
        const auto password = slot_text(payload.subspan(76, 64));
        if (!callbacks_.verify_credentials || !callbacks_.login_responses)
            throw CodecError("lobby_login_provider_not_configured");
        if (!callbacks_.verify_credentials(login.username_utf8, password)) {
            if (original) throw CodecError("lobby_authentication_failed");
            Bytes failure;
            append_le(failure,58,4);
            append_le(failure,std::bit_cast<std::uint32_t>(std::int32_t{-101}),4);
            failure.push_back(0);
            if (log_) log_("lobby_authentication_rejected request_type=58 error_code=-101");
            close();
            return {{0xffffffffU,std::move(failure)}};
        }
        login_ = login;
        auto responses = callbacks_.login_responses(login);
        if (responses.empty()) throw CodecError("lobby_login_response_not_implemented");
        state_ = LobbyState::authenticated;
        if (log_) log_("lobby_authenticated");
        return responses;
    }
    case LobbyState::authenticated:
        if (options_.version == ClientVersion::richonline && frame.wire_type == 0xffffffffU) {
            if (!frame.payload.empty()) throw CodecError("richonline_logout_payload_must_be_empty");
            if (log_) log_("lobby_client_logout");
            close();
            return {};
        }
        if (frame.wire_type == 58 || frame.wire_type == 759)
            throw CodecError("lobby_duplicate_login_or_handshake");
        if (!callbacks_.authenticated_request)
            throw CodecError("lobby_authenticated_handler_not_configured");
        return callbacks_.authenticated_request(*login_, frame);
    case LobbyState::not_started:
    case LobbyState::closed:
        throw CodecError("lobby_session_not_receiving");
    }
    throw CodecError("lobby_invalid_state");
}

std::vector<Bytes> RichLobbySession::feed(View chunk) {
    if (state_ == LobbyState::not_started || state_ == LobbyState::closed)
        throw CodecError("lobby_session_not_receiving");
    std::vector<Bytes> output;
    try {
        while (!chunk.empty()) {
            std::size_t target = 12;
            if (pending_.size() >= 12) {
                const auto size = read_le(View(pending_).subspan(8, 4));
                if (size < 8 || size > max_frame_total) throw CodecError("invalid_frame_total");
                target = static_cast<std::size_t>(size) + 4;
            }
            const auto count = std::min(target - pending_.size(), chunk.size());
            pending_.insert(pending_.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(count));
            chunk = chunk.subspan(count);
            if (pending_.size() < 12) continue;
            if (!std::equal(magic.begin(), magic.end(), pending_.begin()))
                throw CodecError("invalid_lobby_magic");
            const auto size = read_le(View(pending_).subspan(8, 4));
            if (size < 8 || size > max_frame_total) throw CodecError("invalid_frame_total");
            if (pending_.size() != static_cast<std::size_t>(size) + 4) continue;
            auto frame = decode_frame(pending_, {Channel::lobby_c2s, key_, options_.version});
            std::fill(pending_.begin(), pending_.end(), 0);
            pending_.clear();
            try {
                for (auto& notification : drain_outbound()) output.push_back(std::move(notification));
                const auto responses = receive(frame);
                std::fill(frame.payload.begin(), frame.payload.end(), 0);
                encode_responses(responses, output);
                if (state_ == LobbyState::closed) break;
                for (auto& notification : drain_outbound()) output.push_back(std::move(notification));
            } catch (...) {
                std::fill(frame.payload.begin(), frame.payload.end(), 0);
                throw;
            }
        }
    } catch (...) {
        close();
        throw;
    }
    return output;
}

void RichLobbySession::encode_responses(const std::vector<Frame>& frames, std::vector<Bytes>& output) {
    for (const auto& response : frames) {
        output.push_back(encode_frame(response, {Channel::lobby_s2c, key_, options_.version}));
        if (log_) log_("lobby_encoded type=" + std::to_string(response.wire_type) +
                       " payload_bytes=" + std::to_string(response.payload.size()));
        if (log_ && options_.version == ClientVersion::legacy && response.wire_type == 0xffffffffU && response.payload.size() == 136) {
            const auto request_type = read_le(View(response.payload).first(4));
            const auto error_code = std::bit_cast<std::int32_t>(read_le(View(response.payload).subspan(4,4)));
            log_("lobby_request_rejected request_type=" + std::to_string(request_type) + " error_code=" + std::to_string(error_code));
        }
    }
}

std::vector<Bytes> RichLobbySession::drain_outbound() {
    std::vector<Bytes> output;
    if (state_ != LobbyState::authenticated || !callbacks_.drain_outbound) return output;
    try {
        encode_responses(callbacks_.drain_outbound(), output);
    } catch (...) {
        close();
        throw;
    }
    return output;
}

std::vector<Bytes> RichLobbySession::poll() {
    return drain_outbound();
}
void RichLobbySession::sent(View wire_frame) {
    const auto frame=decode_frame(wire_frame,{Channel::lobby_s2c,key_,options_.version});
    if(callbacks_.sent) callbacks_.sent(frame);
    if(log_) log_("lobby_frame_delivered type="+std::to_string(frame.wire_type)+
        " payload_bytes="+std::to_string(frame.payload.size()));
}

void RichLobbySession::close() noexcept {
    std::fill(pending_.begin(), pending_.end(), 0);
    pending_.clear();
    state_ = LobbyState::closed;
    if (disconnected_) return;
    disconnected_ = true;
    try {
        if (callbacks_.disconnected) callbacks_.disconnected();
    } catch (...) {
        // Cleanup runs during unwinding too; neither the callback nor its logger may escape.
        try { if (log_) log_("lobby_disconnect_callback_failed"); } catch (...) {}
    }
}

void RichLobbySession::finish() {
    const bool incomplete = !pending_.empty();
    close();
    if (incomplete) throw CodecError("truncated_lobby_stream");
}

}

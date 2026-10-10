#include "game_session.hpp"
#include "diagnostic_log.hpp"
#include "lua_game.hpp"

#include <exception>
#include <algorithm>
#include <utility>

namespace richnet {
GameSession::GameSession(ClientVersion version, GameCallbacks callbacks, GameLogSink log)
    : version_(version), callbacks_(std::move(callbacks)), log_(nonthrowing_diagnostic_log(std::move(log))),
      decoder_({Channel::game_c2s, {}, version}) {
    switch (version_) {
    case ClientVersion::legacy:
    case ClientVersion::richonline: break;
    default: throw CodecError("invalid_client_version");
    }
    if (version_ == ClientVersion::richonline) callbacks_ = make_lua_game_callbacks(std::move(callbacks_));
}

GameSession::~GameSession() { close(); }

std::vector<Frame> GameSession::receive(const Frame& frame) {
    if (log_) log_("game_received type=" + std::to_string(frame.wire_type) +
                   " payload_bytes=" + std::to_string(frame.payload.size()));
    switch (state_) {
    case GameState::awaiting_admission: {
        // 解码通过不代表授权通过；先与大厅签发的入场凭据匹配，才允许业务消息。
        const auto admission = decode_game_admission(frame, version_);
        if (!callbacks_.authorize_admission) throw CodecError("game_admission_provider_not_configured");
        if (!callbacks_.authorize_admission(admission)) throw CodecError("game_admission_not_authorized");
        admission_ = admission;
        state_ = GameState::admitted;
        if (log_) log_("game_admitted");
        return callbacks_.admitted ? callbacks_.admitted(admission) : std::vector<Frame>{};
    }
    case GameState::admitted: {
        if (frame.wire_type == 0) throw CodecError("game_duplicate_admission");
        const auto envelope = decode_envelope(frame, version_);
        const auto plain = decode_inner(envelope.encoded);
        if (!callbacks_.message) throw CodecError("game_message_handler_not_configured");
        auto responses = callbacks_.message(*admission_, envelope, plain);
        // Only a successfully handled, exact NEW leave signal may close
        // gracefully. Invalid packets still take the ordinary failure path.
        if (version_ == ClientVersion::richonline && plain.size() == 2 && read_le(plain) == 10)
            state_ = GameState::departing;
        return responses;
    }
    case GameState::departing: throw CodecError("game_session_departing");
    case GameState::closed: throw CodecError("game_session_closed");
    }
    throw CodecError("game_invalid_state");
}

std::vector<Bytes> GameSession::feed(View chunk) {
    if (state_ == GameState::closed) throw CodecError("game_session_closed");
    if (state_ == GameState::departing) throw CodecError("game_session_departing");
    std::vector<Bytes> responses;
    try {
        for (const auto& frame : decoder_.feed(chunk)) {
            encode(receive(frame),responses);
            // Requests queued behind an accepted leave cannot mutate a game
            // whose client has already destroyed its board. Preserve the ACK.
            if (state_ == GameState::departing) break;
        }
    } catch (...) {
        // 出错后关闭整个会话，避免半处理状态继续接收下一条游戏操作。
        close();
        throw;
    }
    return responses;
}

void GameSession::encode(const std::vector<Frame>& frames, std::vector<Bytes>& output) {
    for (const auto& reply : frames) {
        output.push_back(encode_frame(reply,{Channel::game_s2c,{},version_}));
        if (callbacks_.sent && (!callbacks_.sent_enabled || callbacks_.sent_enabled(*admission_)))
            pending_sends_.push_back({output.back(),reply});
        if (log_) log_("game_encoded type=" + std::to_string(reply.wire_type) +
                       " payload_bytes=" + std::to_string(reply.payload.size()));
    }
}

std::vector<Bytes> GameSession::poll() {
    std::vector<Bytes> output;
    if (state_ != GameState::admitted || !callbacks_.poll) return output;
    try { encode(callbacks_.poll(*admission_),output); }
    catch (...) { close(); throw; }
    return output;
}

void GameSession::sent(View encoded_frame) {
    if (!callbacks_.sent) return;
    try {
        if (pending_sends_.empty() && admission_ && callbacks_.sent_enabled && !callbacks_.sent_enabled(*admission_)) return;
        if (finished_ || !admission_ || pending_sends_.empty()) throw CodecError("game_sent_without_pending_frame");
        const auto& expected=pending_sends_.front().wire;
        if (!std::equal(encoded_frame.begin(),encoded_frame.end(),expected.begin(),expected.end()))
            throw CodecError("game_sent_frame_out_of_order");
        auto confirmed=std::move(pending_sends_.front().frame);
        pending_sends_.pop_front();
        callbacks_.sent(*admission_,confirmed);
        if (log_) log_("game_transport_sent type="+std::to_string(confirmed.wire_type)+
            " payload_bytes="+std::to_string(confirmed.payload.size()));
    } catch (...) { close(); throw; }
}

void GameSession::close() noexcept {
    // 主动关闭、收包失败和析构共用此入口，离线回调最多执行一次。
    if (finished_) return;
    finished_ = true;
    state_ = GameState::closed;
    pending_sends_.clear();
    const auto admission = std::exchange(admission_,{});
    try { if (admission && callbacks_.disconnected) callbacks_.disconnected(*admission); }
    catch (...) {
        try { if (log_) log_("game_disconnect_callback_failed"); } catch (...) {}
    }
}

void GameSession::finish() {
    if (finished_) return;
    // Bytes trailing a completed leave belong to a connection being retired;
    // a partial trailing frame must not turn a successful departure into an
    // unrelated truncated-frame error.
    if (state_ == GameState::departing) { close(); return; }
    std::exception_ptr error;
    try { decoder_.finish(); } catch (...) { error = std::current_exception(); }
    close();
    if (error) std::rethrow_exception(error);
}
}

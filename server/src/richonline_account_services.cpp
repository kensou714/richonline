#include "richonline_account_services.hpp"
#include "richonline_lobby_error.hpp"
#include <bit>
#include <cmath>
#include <limits>

namespace richnet {
namespace {
double read_f64(View data, std::size_t offset) {
    if (offset + 8 > data.size()) throw CodecError("richonline_account_config_short");
    std::uint64_t bits = 0;
    for (std::size_t i=0;i<8;++i) bits |= static_cast<std::uint64_t>(data[offset+i]) << (8*i);
    const auto result=std::bit_cast<double>(bits);
    if (!std::isfinite(result)) throw CodecError("richonline_account_config_nonfinite");
    return result;
}
double request_amount(View payload) {
    if (payload.size()!=8) throw CodecError("richonline_account_amount_length");
    return read_f64(payload,0);
}
RichonlineAccountReply failed(std::uint32_t wire, std::int32_t reason, std::string text) {
    return {richonline_lobby_failure(wire,reason),std::nullopt,std::move(text)};
}
}

RichonlineAccountPolicy richonline_account_policy(View bank_config, View completion) {
    if (bank_config.size()!=32 || completion.size()!=28)
        throw CodecError("richonline_account_policy_length_invalid");
    // NEW dispatch stores bank config as f64 at +0,+8,+16,+24; +0 is a display value.
    const BankLimits limits{read_f64(bank_config,8),read_f64(bank_config,16),read_f64(bank_config,24)};
    if (!valid_bank_limits(limits)) throw CodecError("richonline_bank_limits_invalid");
    // Completion wire30 stores exchange divisor at +20. NEW 8ADA10 subtracts
    // gold_delta / divisor from the cached M-points balance.
    const auto divisor=read_f64(completion,20);
    if (!(divisor > 0))
        throw CodecError("richonline_exchange_ratio_invalid");
    return {limits,divisor};
}

Frame richonline_account_error(std::uint32_t request_type, std::int32_t reason) {
    return richonline_lobby_failure(request_type,reason);
}

std::optional<RichonlineAccountReply> richonline_account_request(
    Storage& storage, const std::string& username, std::uint32_t role_id,
    const Frame& request, const RichonlineAccountPolicy& policy) {
    if (request.wire_type!=42 && request.wire_type!=61 && request.wire_type!=62) return std::nullopt;
    if (storage.client_profile()!=ClientProfile::richonline)
        throw CodecError("richonline_account_profile_required");
    if (request.payload.size()!=(request.wire_type==42 ? 16U : 8U))
        throw CodecError("richonline_account_request_length_invalid");
    if (request.wire_type==42 && (read_le(View(request.payload).first(4))!=1 ||
        read_le(View(request.payload).subspan(4,4))!=2))
        throw CodecError("richonline_exchange_currency_pair_invalid");
    try {
        if (request.wire_type==61 || request.wire_type==62) {
            const auto amount=request_amount(request.payload);
            const BankTransfer transfer{request.wire_type==61 ? BankDirection::deposit : BankDirection::withdraw,amount,policy.bank};
            const auto status=storage.transfer_bank(username,role_id,transfer);
            switch(status) {
            case BankStatus::success: return RichonlineAccountReply{{request.wire_type==61 ? 101U : 102U,request.payload},std::nullopt,{}};
            case BankStatus::invalid_amount: return failed(request.wire_type,-131,"invalid bank amount");
            case BankStatus::insufficient_funds: return failed(request.wire_type,-124,"insufficient bank balance");
            case BankStatus::capacity_exceeded: return failed(request.wire_type,-123,"bank capacity exceeded");
            }
        }
        const auto amount=request_amount(View(request.payload).subspan(8,8));
        const auto result=storage.exchange_gold(username,role_id,{amount,policy.exchange_ratio});
        switch(result.status) {
        case ExchangeStatus::success: {
            Bytes payload; append_le(payload,1,4); append_le(payload,2,4);
            payload.insert(payload.end(),request.payload.begin()+8,request.payload.end());
            const auto delta=amount*policy.exchange_ratio; const auto bits=std::bit_cast<std::uint64_t>(delta);
            for(std::size_t i=0;i<8;++i) payload.push_back(static_cast<std::uint8_t>(bits>>(8*i)));
            return RichonlineAccountReply{{79,std::move(payload)},result.role,{}};
        }
        // NEW 6B1370 displays the same failure for all reasons. -112 is our
        // documented generic failure policy, not an inferred exchange-specific enum.
        case ExchangeStatus::invalid_amount: return failed(42,-112,"invalid exchange amount");
        case ExchangeStatus::insufficient_funds: return failed(42,-112,"insufficient M points");
        }
    } catch (const StorageError& error) {
        return failed(request.wire_type,-112,error.what());
    } catch (const CodecError&) {
        return failed(request.wire_type,request.wire_type==42 ? -112 : -131,"nonfinite account amount");
    }
    throw CodecError("richonline_account_status_unreachable");
}
}

#include "original_bank.hpp"

#include <bit>

namespace richnet {
namespace {
double read_double(View bytes) {
    if (bytes.size() != 8) throw CodecError("original_bank_amount_length_invalid");
    std::uint64_t bits = 0;
    for (std::size_t i = 0; i < 8; ++i) bits |= static_cast<std::uint64_t>(bytes[i]) << (8 * i);
    return std::bit_cast<double>(bits);
}
}
BankLimits original_bank_limits(View config) {
    if (config.size() != 32) throw CodecError("original_bank_config_length_invalid");
    const BankLimits limits{read_double(config.subspan(8,8)),read_double(config.subspan(16,8)),read_double(config.subspan(24,8))};
    if (!valid_bank_limits(limits)) throw CodecError("original_bank_limits_invalid");
    return limits;
}
Frame original_bank_response(Storage& storage, const std::string& username, std::uint32_t role_id,
                             const Frame& request, const BankLimits& limits) {
    if (request.wire_type != 61 && request.wire_type != 62) throw CodecError("original_bank_request_type_invalid");
    const BankTransfer transfer{request.wire_type == 61 ? BankDirection::deposit : BankDirection::withdraw,
        read_double(request.payload),limits};
    const auto result = storage.transfer_bank(username,role_id,transfer);
    std::int32_t code;
    switch (result) {
    case BankStatus::success: return {request.wire_type == 61 ? 101U : 102U,request.payload};
    case BankStatus::invalid_amount: code = -131; break;
    case BankStatus::insufficient_funds: code = -124; break;
    case BankStatus::capacity_exceeded: code = -123; break;
    }
    return original_business_error(request.wire_type,code);
}
Frame original_business_error(std::uint32_t request_type, std::int32_t error_code) {
    if (request_type != 42 && request_type != 61 && request_type != 62)
        throw CodecError("original_business_error_context_not_verified");
    Bytes error;
    append_le(error,request_type,4);
    append_le(error,static_cast<std::uint32_t>(error_code),4);
    // Original 7ED790 ignores context for requests42/61/62; all-zero denotes no text context.
    error.resize(136,0);
    return {0xffffffffU,std::move(error)};
}
}

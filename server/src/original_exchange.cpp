#include "original_exchange.hpp"
#include <bit>

namespace richnet {
OriginalExchangeResult original_exchange_response(Storage& storage, const std::string& username,
    std::uint32_t role_id, const Frame& request, std::int32_t ratio) {
    if (request.wire_type != 42) throw CodecError("original_exchange_request_type_invalid");
    const auto fail = [](std::int32_t code) -> OriginalExchangeResult {
        return {original_business_error(42,code),std::nullopt};
    };
    const auto data = View(request.payload);
    if (data.size() != 24 || read_le(data.first(4)) != 1 || read_le(data.subspan(4,4)) != 2 ||
        read_le(data.subspan(16,4)) != 0 || read_le(data.subspan(20,4)) != 0) return fail(-10);
    std::uint64_t bits = 0;
    for (std::size_t i=0;i<8;++i) bits |= static_cast<std::uint64_t>(data[8+i]) << (8*i);
    const double amount = std::bit_cast<double>(bits);
    auto result = storage.exchange_gold(username,role_id,{amount,ratio});
    switch (result.status) {
    case ExchangeStatus::invalid_amount: return fail(-10);
    case ExchangeStatus::insufficient_funds: return fail(-124);
    case ExchangeStatus::success: break;
    }
    Bytes response;
    append_le(response,1,4);
    // Original 7ED9E0 copies +4 but never reads it; zero is the local canonical unused word.
    append_le(response,0,4);
    for (const auto value : {amount,amount*ratio}) {
        const auto encoded = std::bit_cast<std::uint64_t>(value);
        for (std::size_t i=0;i<8;++i) response.push_back(static_cast<std::uint8_t>(encoded >> (8*i)));
    }
    return {{79,std::move(response)},std::move(result.role)};
}
}

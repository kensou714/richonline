#pragma once
#include "original_inventory.hpp"
#include <variant>

namespace richnet {
struct OriginalShopChoice { std::uint16_t context; std::int8_t index; std::uint8_t opaque; };
struct OriginalShopSale { std::uint16_t context; std::int8_t slot; std::uint8_t opaque; };
struct OriginalCardDiscard { std::uint16_t context; std::int8_t slot; std::uint8_t opaque; };
struct OriginalShopRefresh { std::uint16_t context; };
using OriginalShopRequest = std::variant<OriginalShopChoice,OriginalShopSale,OriginalCardDiscard,OriginalShopRefresh>;
struct OriginalShopStock {
    std::uint16_t instance;
    std::array<OriginalCardSlot,12> slots;
    bool refresh;
};
OriginalShopRequest parse_original_shop_request(View plain);
Bytes encode_original_shop_stock(const OriginalShopStock& stock);
Bytes encode_original_shop_choice(std::uint16_t instance, std::int8_t index);
Bytes encode_original_shop_sale(std::uint16_t instance, std::int8_t slot);
Bytes encode_original_card_discard(std::uint16_t instance, std::uint8_t slot, std::uint8_t owner);
Bytes encode_original_card_grant(std::uint16_t instance, std::int16_t card);
}

#pragma once
#include "original_card_resources.hpp"
#include "original_map.hpp"
#include <functional>

namespace richnet {
struct RichonlineShopOffer {
    std::int16_t card_id=-1, count=0;
    bool operator==(const RichonlineShopOffer&) const = default;
};
using RichonlineShopStock=std::array<RichonlineShopOffer,12>;
class RichonlineShopCatalog final {
public:
    using Choose=std::function<std::size_t(std::size_t)>;
    static RichonlineShopCatalog parse(const OriginalPropCards& props,const OriginalEmp& map);
    static RichonlineShopCatalog load(const std::filesystem::path& root,std::string_view map_name);
    const std::vector<RichonlineShopOffer>& offers() const noexcept { return offers_; }
    // 出售按同一价格表退还 priceG/2；saleG 只控制商店进货，不代表玩家能否出售。
    bool can_sell(std::int16_t card_id) const noexcept { return prices_.contains(card_id); }
    std::uint32_t price(std::int16_t card_id) const;
    // Uniform selection without replacement is an explicit emulator policy.
    RichonlineShopStock select(const Choose& choose) const;
private:
    std::map<std::int16_t,std::uint32_t> prices_;
    std::vector<RichonlineShopOffer> offers_;
};
}

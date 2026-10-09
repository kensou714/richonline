#include "richonline_shop_catalog.hpp"
#include <algorithm>
#include <set>

namespace richnet {
RichonlineShopCatalog RichonlineShopCatalog::parse(const OriginalPropCards& props,const OriginalEmp& map) {
    const View bytes(map.payload);
    auto cursor=map.tail_offset;
    const auto skip=[&](std::size_t count,std::size_t stride) {
        if (cursor>bytes.size() || count>(bytes.size()-cursor)/stride) throw CodecError("richonline_shop_map_truncated");
        cursor+=count*stride;
    };
    const auto word=[&] { skip(1,4); return read_le(bytes.subspan(cursor-4,4)); };
    // NEW 7DF010: 120-byte values, a DWORD array, then count + eight-byte card rows.
    skip(120,1); const auto unknown_count=word(); skip(unknown_count,4);
    const auto card_count=word();
    if (card_count>32768) throw CodecError("richonline_shop_map_count_invalid");
    std::set<std::int16_t> allowed;
    for (std::uint32_t i=0;i<card_count;++i) {
        const auto card=word(); skip(1,4);
        if (card==0 || card>32767 || !allowed.insert(static_cast<std::int16_t>(card)).second)
            throw CodecError("richonline_shop_map_card_invalid");
    }
    RichonlineShopCatalog result;
    for (const auto& card:props.cards) {
        if (card.id<=0 || (card.price_g && *card.price_g<0))
            throw CodecError("richonline_shop_price_invalid");
        if (!card.price_g) {
            if (allowed.contains(card.id) && card.enabled.value_or(false) && card.sale_g.value_or(false))
                throw CodecError("richonline_shop_price_missing");
            continue;
        }
        if (!result.prices_.emplace(card.id,static_cast<std::uint32_t>(*card.price_g)).second)
            throw CodecError("richonline_shop_card_duplicate");
        if (!allowed.contains(card.id) || !card.enabled.value_or(false) || !card.sale_g.value_or(false)) continue;
        const auto count=card.fold.value_or(1);
        if (count<1 || count>32767) throw CodecError("richonline_shop_count_invalid");
        result.offers_.push_back({card.id,static_cast<std::int16_t>(count)});
    }
    if (result.offers_.empty()) throw CodecError("richonline_shop_catalog_empty");
    // Existing test-game deployments keep the controlled die first; remaining offers retain resource order.
    const auto controlled=std::find_if(result.offers_.begin(),result.offers_.end(),[](const auto& offer) { return offer.card_id==1038; });
    if (controlled!=result.offers_.end()) std::rotate(result.offers_.begin(),controlled,controlled+1);
    return result;
}
RichonlineShopCatalog RichonlineShopCatalog::load(const std::filesystem::path& root,std::string_view name) {
    const std::filesystem::path filename(name);
    if (filename.has_parent_path() || filename.extension()!=".emp") throw CodecError("richonline_shop_map_name_invalid");
    return parse(load_original_prop_cards(root/"Data"/"Prop.kpd"),load_original_emp(root/"Map"/filename));
}
std::uint32_t RichonlineShopCatalog::price(std::int16_t card) const {
    const auto found=prices_.find(card);
    if (found==prices_.end()) throw CodecError("richonline_shop_price_unknown");
    return found->second;
}
RichonlineShopStock RichonlineShopCatalog::select(const Choose& choose) const {
    if (!choose) throw CodecError("richonline_shop_random_required");
    auto remaining=offers_;
    RichonlineShopStock stock;
    for (auto& offer:stock) {
        if (remaining.empty()) break;
        const auto index=choose(remaining.size());
        if (index>=remaining.size()) throw CodecError("richonline_shop_random_invalid");
        offer=remaining[index]; remaining.erase(remaining.begin()+static_cast<std::ptrdiff_t>(index));
    }
    return stock;
}
}

#pragma once
#include "codec.hpp"
#include <filesystem>
#include <map>
#include <string>

namespace richnet {
enum class RichonlineMallCurrency : std::uint32_t { m_points=1, gold=2 };
struct RichonlineMallTerm { std::uint32_t years,months,days; };
struct RichonlineMallProduct {
    std::uint16_t id;
    std::string type,subtype,name_bytes;
    bool enabled;
    std::array<bool,2> sale;
    std::array<double,2> price;
    std::array<RichonlineMallTerm,2> term;
    std::uint32_t fold,score,level;
    std::map<std::string,std::string> source_fields;
};
struct RichonlineMallOffer { std::string group; std::uint16_t product; RichonlineMallCurrency currency; };
// Prices and availability come from the NEW client's Prop/SellProp resources.
// This does not invent the unresolved inventory-key date encoding or a purchase ACK.
class RichonlineMallCatalog final {
public:
    static RichonlineMallCatalog parse(View props,View sale);
    static RichonlineMallCatalog load(const std::filesystem::path& client_root);
    const std::map<std::uint16_t,RichonlineMallProduct>& products() const noexcept { return products_; }
    const std::vector<RichonlineMallOffer>& offers() const noexcept { return offers_; }
    const RichonlineMallProduct& purchasable(std::uint32_t encoded_request_item) const;
    double activation_charge(std::uint32_t owned_key,RichonlineMallCurrency currency) const;
    std::uint32_t activation_days(std::uint32_t owned_key) const;
private:
    std::map<std::uint16_t,RichonlineMallProduct> products_;
    std::vector<RichonlineMallOffer> offers_;
};
}

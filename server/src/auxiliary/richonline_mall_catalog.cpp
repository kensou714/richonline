#include "richonline_mall_catalog.hpp"
#include "original_options.hpp"
#include <algorithm>
#include <charconv>
#include <cmath>
#include <set>

namespace richnet {
namespace {
using Fields=std::map<std::string,std::string>;
struct Section { std::string name; Fields fields; };
constexpr std::size_t limit=4U*1024U*1024U;
std::string_view trim(std::string_view value) {
    const auto first=value.find_first_not_of(" \r\t");
    return first==std::string_view::npos ? std::string_view{} : value.substr(first,value.find_last_not_of(" \r\t")-first+1);
}
std::vector<Section> sections(View bytes) {
    if(bytes.empty()||bytes.size()>limit||std::find(bytes.begin(),bytes.end(),0)!=bytes.end())throw CodecError("mall_resource_text_invalid");
    std::string_view input(reinterpret_cast<const char*>(bytes.data()),bytes.size());
    std::vector<Section> result;
    while(!input.empty()) {
        const auto newline=input.find('\n');const auto line=trim(input.substr(0,newline));
        input=newline==std::string_view::npos ? std::string_view{} : input.substr(newline+1);
        if(line.empty()||line.starts_with("//")||line.front()==';'||line.front()=='#')continue;
        if(line.front()=='[') {
            if(line.back()!=']'||line.size()<3||result.size()>=8192)throw CodecError("mall_resource_section_invalid");
            result.push_back({std::string(trim(line.substr(1,line.size()-2))),{}});continue;
        }
        const auto separator=line.find('=');
        if(result.empty()||separator==std::string_view::npos||result.back().fields.size()>=256)throw CodecError("mall_resource_field_invalid");
        const auto key=trim(line.substr(0,separator));
        if(key.empty()||!result.back().fields.emplace(key,trim(line.substr(separator+1))).second)throw CodecError("mall_resource_duplicate_field");
    }
    return result;
}
std::string_view required(const Fields& fields,const char* name) {
    const auto found=fields.find(name);if(found==fields.end())throw CodecError("mall_resource_field_missing");return found->second;
}
std::uint32_t integer(std::string_view value) {
    std::uint32_t number{};const auto parsed=std::from_chars(value.data(),value.data()+value.size(),number);
    if(value.empty()||parsed.ec!=std::errc{}||parsed.ptr!=value.data()+value.size())throw CodecError("mall_resource_integer_invalid");return number;
}
std::uint32_t optional_integer(const Fields& fields,const char* key,std::uint32_t initial=0) {
    const auto found=fields.find(key);return found==fields.end() ? initial : integer(found->second);
}
bool boolean(const Fields& fields,const char* key,bool first_component=false) {
    const auto found=fields.find(key);if(found==fields.end())return false;
    auto value=std::string_view(found->second);if(first_component)value=value.substr(0,value.find(','));
    if(value!="true"&&value!="false")throw CodecError("mall_resource_boolean_invalid");return value=="true";
}
double price(const Fields& fields,const char* key) {
    const auto found=fields.find(key);if(found==fields.end())return 0.0;
    const auto& value=found->second;double number{};const auto parsed=std::from_chars(value.data(),value.data()+value.size(),number);
    if(parsed.ec!=std::errc{}||parsed.ptr!=value.data()+value.size()||!std::isfinite(number)||number<0)throw CodecError("mall_resource_price_invalid");return number;
}
RichonlineMallTerm term(const Fields& fields,const char* year,const char* month,const char* day) {
    return {optional_integer(fields,year),optional_integer(fields,month),optional_integer(fields,day)};
}
}
RichonlineMallCatalog RichonlineMallCatalog::parse(View props,View sale,View awards) {
    RichonlineMallCatalog result;
    for(auto& section:sections(props)) {
        if(section.name!="PROP")throw CodecError("mall_resource_prop_section_invalid");
        auto& fields=section.fields;const auto id=integer(required(fields,"indx"));
        if(id==0||id>4095)throw CodecError("mall_resource_product_id_invalid");
        // Defaults below are the NEW constructor 7FE7D0, not placeholder values.
        RichonlineMallProduct product{static_cast<std::uint16_t>(id),std::string(required(fields,"type")),
            std::string(required(fields,"chType")),std::string(required(fields,"name")),boolean(fields,"enable",true),
            {boolean(fields,"saleLJ"),boolean(fields,"saleLR")},{price(fields,"priceLJ"),price(fields,"priceLR")},
            {term(fields,"yearJ","monthJ","dayJ"),term(fields,"yearR","monthR","dayR")},
            optional_integer(fields,"fold",1),optional_integer(fields,"score"),optional_integer(fields,"level"),std::move(fields)};
        if(product.fold==0)throw CodecError("mall_resource_fold_invalid");
        if(!result.products_.emplace(product.id,std::move(product)).second)throw CodecError("mall_resource_product_duplicate");
    }
    static const std::set<std::string> groups{"C_GL","C_CQ","F","A_BS","A_BJ","A_TX","A_FS","A_QC","A_CW","A_ZJ"};
    for(const auto& section:sections(sale)) {
        const auto& group=section.name;
        if(group.size()<3||group[group.size()-2]!='_'||!groups.contains(group.substr(0,group.size()-2))||
            (group.back()!='J'&&group.back()!='R'))throw CodecError("mall_resource_sale_group_invalid");
        const auto id=integer(required(section.fields,"prop"));
        if(id>4095||!result.products_.contains(static_cast<std::uint16_t>(id)))throw CodecError("mall_resource_sale_product_missing");
        const auto product=static_cast<std::uint16_t>(id);
        // 801680 appends every section in order, including repeated offers.
        result.offers_.push_back({group,product,group.back()=='J'?RichonlineMallCurrency::m_points:RichonlineMallCurrency::gold});
    }
    if(!awards.empty()) for(const auto& section:sections(awards)) {
        if(section.name!="AWARD") throw CodecError("mall_bag_section_invalid");
        const auto bag=integer(required(section.fields,"bagID"));
        if(bag<105 || bag>107 || !result.products_.contains(static_cast<std::uint16_t>(bag)))
            throw CodecError("mall_bag_id_unsupported");
        std::array<RichonlineMallBagSlot,16> slots{};
        for(std::size_t index=0;index<slots.size();++index) {
            const auto name="item"+std::to_string(index+3);
            auto text=required(section.fields,name.c_str());
            const auto first=text.find_first_of(" \t");
            if(first==text.npos) throw CodecError("mall_bag_slot_invalid");
            const auto product=integer(text.substr(0,first));text=trim(text.substr(first));
            const auto second=text.find_first_of(" \t");
            if(second==text.npos) throw CodecError("mall_bag_slot_invalid");
            const auto opaque=integer(text.substr(0,second));text=trim(text.substr(second));
            if(product==0 || product>4095 || !result.products_.contains(static_cast<std::uint16_t>(product)) ||
                (text!="true" && text!="false")) throw CodecError("mall_bag_slot_invalid");
            slots[index]={static_cast<std::uint16_t>(product),opaque,text=="true"};
        }
        if(!result.bags_.emplace(static_cast<std::uint16_t>(bag),slots).second)
            throw CodecError("mall_bag_duplicate");
    }
    return result;
}
RichonlineMallCatalog RichonlineMallCatalog::load(const std::filesystem::path& root) {
    const auto props=load_original_kpd(root/"Data"/"Prop.kpd",limit),sale=load_original_kpd(root/"Data"/"SellProp.kpd",limit);
    const auto awards=load_original_kpd(root/"Data"/"AwardLB.kpd",limit);
    return parse(props,sale,awards);
}
const RichonlineMallProduct& RichonlineMallCatalog::purchasable(std::uint32_t key) const {
    if((key&0xffff0000U)!=0)throw CodecError("mall_purchase_metadata_unproven");
    const auto mode=(key>>12U)&15U;if(mode!=1&&mode!=2)throw CodecError("mall_purchase_currency_invalid");
    const auto found=products_.find(static_cast<std::uint16_t>(key&4095U));
    if(found==products_.end())throw CodecError("mall_purchase_product_missing");
    const auto& product=found->second;
    const auto listed=std::any_of(offers_.begin(),offers_.end(),[&](const auto& offer){return offer.product==product.id&&static_cast<std::uint32_t>(offer.currency)==mode;});
    if(!listed||!product.enabled||!product.sale.at(mode-1))throw CodecError("mall_purchase_product_unavailable");
    return product;
}
double RichonlineMallCatalog::activation_charge(std::uint32_t key,RichonlineMallCurrency currency) const {
    const auto mode=static_cast<std::uint32_t>(currency);
    if(mode!=1&&mode!=2)throw CodecError("mall_activation_currency_invalid");
    if((key&0x40000000U)==0||(key&0x10000U)!=0)throw CodecError("mall_activation_item_state_invalid");
    const auto source=(key>>12U)&15U;
    if(source>2)throw CodecError("mall_activation_source_currency_invalid");
    const auto found=products_.find(static_cast<std::uint16_t>(key&4095U));
    if(found==products_.end())throw CodecError("mall_activation_product_missing");
    // NEW 766B50 chooses the activation tariff by the item's original currency.
    static constexpr std::array<const char*,3> points{"jhdbP","jhdbJ","jhdbR"};
    static constexpr std::array<const char*,3> beans{"beanP","beanJ","beanR"};
    const auto charge=optional_integer(found->second.source_fields,(mode==1?points:beans).at(source));
    if(charge==0)throw CodecError("mall_activation_currency_unavailable");
    return static_cast<double>(charge);
}
std::uint32_t RichonlineMallCatalog::activation_days(std::uint32_t key) const {
    const auto source=(key>>12U)&15U;if(source>2)throw CodecError("mall_activation_source_currency_invalid");
    const auto found=products_.find(static_cast<std::uint16_t>(key&4095U));
    if(found==products_.end())throw CodecError("mall_activation_product_missing");
    static constexpr std::array<const char*,3> names{"jhDayP","jhDayJ","jhDayR"};
    return optional_integer(found->second.source_fields,names.at(source));
}
const std::array<RichonlineMallBagSlot,16>& RichonlineMallCatalog::bag_slots(std::uint16_t bag) const {
    const auto found=bags_.find(bag);
    if(found==bags_.end()) throw CodecError("mall_bag_awards_missing");
    return found->second;
}
RichonlineMallTerm RichonlineMallCatalog::gift_term(std::uint16_t id) const {
    const auto found=products_.find(id);
    if(found==products_.end() || !found->second.enabled) throw CodecError("mall_gift_product_unavailable");
    // 沿用BOSS宝箱赠品政策；不把购买价格、fold或AwardLB第二字段当作奖励期限。
    return term(found->second.source_fields,"yearP","monthP","dayP");
}
}

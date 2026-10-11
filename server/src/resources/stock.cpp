#include "richonline_stock_resources.hpp"
#include "original_options.hpp"
#include "lua_wire.hpp"
#include <algorithm>
#include <bit>
#include <charconv>
#include <cmath>
#include <map>
#include <set>
#include <utility>

namespace richnet {
namespace {
constexpr std::size_t text_limit=4U*1024U*1024U;
using Fields=std::map<std::string,std::string,std::less<>>;
std::string_view trim(std::string_view text) {
    const auto start=text.find_first_not_of(" \t\r");
    return start==text.npos ? std::string_view{} : text.substr(start,text.find_last_not_of(" \t\r")-start+1);
}
std::string_view required(const Fields& fields,std::string_view key) {
    const auto found=fields.find(key);
    if(found==fields.end()) throw CodecError("richonline_stock_resource_field_missing");
    return found->second;
}
template<class T> T number(std::string_view text) {
    T result{};
    const auto parsed=std::from_chars(text.data(),text.data()+text.size(),result);
    if(text.empty() || parsed.ec!=std::errc{} || parsed.ptr!=text.data()+text.size())
        throw CodecError("richonline_stock_resource_number_invalid");
    return result;
}
void positive(float value) {
    if(!std::isfinite(value) || value<=0) throw CodecError("richonline_stock_opening_price_invalid");
}
std::uint32_t word(View bytes,std::size_t offset) {
    if(offset>bytes.size() || bytes.size()-offset<4) throw CodecError("richonline_stock_map_truncated");
    return read_le(bytes.subspan(offset,4));
}
void floating(Bytes& bytes,float value) {append_le(bytes,std::bit_cast<std::uint32_t>(value),4);}
}
RichonlineStockResources parse_richonline_stock_resources(std::string_view text) {
    if(text.empty() || text.size()>text_limit || text.find('\0')!=text.npos)
        throw CodecError("richonline_stock_resource_text_invalid");
    struct Section {std::string name;Fields fields;};
    std::vector<Section> sections;
    while(!text.empty()) {
        const auto newline=text.find('\n');const auto line=trim(text.substr(0,newline));
        text=newline==text.npos ? std::string_view{} : text.substr(newline+1);
        if(line.empty() || line.starts_with("//") || line.front()==';' || line.front()=='#') continue;
        if(line.size()>4096) throw CodecError("richonline_stock_resource_line_invalid");
        if(line.front()=='[') {
            if((line!="[RANGE]" && line!="[STOCK]") || sections.size()>=4097)
                throw CodecError("richonline_stock_resource_section_invalid");
            sections.push_back({std::string(line),{}});continue;
        }
        const auto split=line.find_first_of("=:");
        if(sections.empty() || split==line.npos) throw CodecError("richonline_stock_resource_line_invalid");
        const auto key=trim(line.substr(0,split));
        if(key.empty() || key.find_first_not_of("abcdefghijklmnopqrstuvwxyz_")!=key.npos ||
            !sections.back().fields.emplace(key,trim(line.substr(split+1))).second)
            throw CodecError("richonline_stock_resource_field_invalid");
    }
    RichonlineStockResources result;
    const auto count=static_cast<std::size_t>(std::count_if(sections.begin(),sections.end(),
        [](const auto& s){return s.name=="[STOCK]";}));
    if(count==0 || count>4096) throw CodecError("richonline_stock_resource_count_invalid");
    result.definitions.resize(count);std::set<std::uint32_t> indices;bool range_seen=false;
    for(const auto& section:sections) {
        const auto& fields=section.fields;
        if(section.name=="[RANGE]") {
            if(range_seen) throw CodecError("richonline_stock_resource_range_duplicate");
            range_seen=true;
            if(fields.contains("rise")) result.rise_limit=number<float>(required(fields,"rise"));
            if(fields.contains("drop")) result.fall_limit=number<float>(required(fields,"drop"));
            continue;
        }
        const auto index=number<std::uint32_t>(required(fields,"indx"));
        if(index>=count || !indices.insert(index).second) throw CodecError("richonline_stock_resource_index_invalid");
        const auto name=required(fields,"name");
        const auto assets=number<std::uint32_t>(required(fields,"asset"));
        const auto shares=number<std::uint32_t>(required(fields,"gushu"));
        const auto activity=number<float>(required(fields,"huopo"));
        if(name.empty() || name.size()>31 || assets==0 || assets>2147483647U || shares==0 ||
            shares>2147483647U || !std::isfinite(activity) || activity<0)
            throw CodecError("richonline_stock_resource_value_invalid");
        result.definitions[index]={std::string(name),assets,shares,activity};
    }
    if(!std::isfinite(result.rise_limit) || !std::isfinite(result.fall_limit) ||
        result.rise_limit<=0 || result.fall_limit>=0) throw CodecError("richonline_stock_resource_range_invalid");
    return result;
}
RichonlineStockResources load_richonline_stock_resources(const std::filesystem::path& root) {
    const auto bytes=load_original_kpd(root/"Data"/"Stock.kpd",text_limit);
    return parse_richonline_stock_resources({reinterpret_cast<const char*>(bytes.data()),bytes.size()});
}
RichonlineStockMap richonline_stock_map(const OriginalEmp& map) {
    if(map.version<1 || map.version>3 || word(map.header,16)!=map.version)
        throw CodecError("richonline_stock_map_version_invalid");
    const auto type=word(map.header,23288);
    const bool enabled=type==0 || (type==2 && map.version>=2 && word(map.header,23296)==0);
    // 7DF010先消费尾部120字节的坐标/资金，再读数量和DWORD配置编号数组。
    if(map.tail_offset>map.payload.size()) throw CodecError("richonline_stock_map_truncated");
    const auto tail=View(map.payload).subspan(map.tail_offset);
    const auto count=word(tail,120);
    if(count>10 || tail.size()-124<static_cast<std::size_t>(count)*4)
        throw CodecError("richonline_stock_map_count_invalid");
    RichonlineStockMap result{enabled,{}};std::set<std::uint32_t> indices;
    for(std::size_t slot=0;slot<count;++slot) {
        const auto index=word(tail,124+slot*4);
        if(index>2147483647U || !indices.insert(index).second)
            throw CodecError("richonline_stock_map_index_invalid");
        result.configurations.push_back(index);
    }
    return result;
}
RichonlineStockOpening prepare_richonline_stock_opening(std::uint16_t game,
    const RichonlineStockResources& resources,const RichonlineStockMap& map,std::span<const RichonlineStockHistory> history,
    float previous_index,float current_index,float factor,std::shared_ptr<RichonlineGameLedger> ledger,
    std::shared_ptr<LuaServer> script) {
    if(!map.enabled || map.configurations.empty() || map.configurations.size()>10 || history.size()!=map.configurations.size())
        throw CodecError("richonline_stock_opening_map_invalid");
    positive(previous_index);positive(current_index);
    if(!std::isfinite(factor))
        throw CodecError("richonline_stock_opening_index_invalid");
    richonline_stock_change_percent(previous_index,current_index);
    std::vector<RichonlineStockQuote> quotes;std::vector<Bytes> messages;
    auto rows=LuaValue::array();
    Bytes index;append_le(index,0x4200,2);append_le(index,game,2);
    floating(index,previous_index);floating(index,current_index);floating(index,factor);
    messages.push_back(std::move(index));
    for(std::size_t slot=0;slot<history.size();++slot) {
        const auto configuration=map.configurations[slot];const auto& prices=history[slot].prices;
        if(configuration>=resources.definitions.size() || history[slot].configuration!=configuration)
            throw CodecError("richonline_stock_opening_configuration_invalid");
        for(const auto price:prices) positive(price);
        const auto [low,high]=std::minmax_element(prices.begin(),prices.end());
        if(*low==*high) throw CodecError("richonline_stock_opening_flat_history");
        // 4201直接取最后两点，不使用4203的涨跌幅内阈值修饰。
        const float change=richonline_stock_change_percent(prices[28],prices[29]);
        quotes.push_back({static_cast<std::int32_t>(configuration),resources.definitions[configuration].shares,prices[29],change});
        Bytes response;append_le(response,0x4201,2);append_le(response,game,2);
        append_le(response,static_cast<std::uint32_t>(slot),2);append_le(response,0,2);
        for(const auto price:prices) floating(response,price);
        messages.push_back(std::move(response));rows.push_back({{"slot",slot},{"prices",prices}});
    }
    if(script) {
        const auto result=script->call("stock.open",{{"game_id",game},{"previous_index",previous_index},
            {"current_index",current_index},{"factor",factor},{"history",rows}});
        auto expected=LuaValue::array();for(const auto& message:messages) expected.push_back(lua_bytes(View(message)));
        if(result!=expected) throw CodecError("lua_stock_opening_invalid");
    }
    // 全部行情包验证完成后才创建交易状态；上层不得在客户端收齐之前开放交易。
    auto market=std::make_shared<RichonlineStockMarket>(game,std::move(ledger),std::move(quotes),
        resources.rise_limit,resources.fall_limit,RichonlineStockIndex{previous_index,current_index,factor},std::move(script));
    return {std::move(market),std::move(messages)};
}
}

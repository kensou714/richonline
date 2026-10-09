#include "richonline_chance_events.hpp"
#include "original_options.hpp"
#include <algorithm>
#include <charconv>
#include <limits>

namespace richnet {
namespace {
std::vector<std::string_view> split(std::string_view text,char delimiter) {
    std::vector<std::string_view> result;
    for (;;) { const auto at=text.find(delimiter); result.push_back(text.substr(0,at));
        if(at==text.npos) return result; text.remove_prefix(at+1); }
}
std::string_view trim(std::string_view text) {
    const auto first=text.find_first_not_of(" \t\r");
    return first==text.npos ? std::string_view{} : text.substr(first,text.find_last_not_of(" \t\r")-first+1);
}
std::int32_t number(std::string_view text) {
    text=trim(text); std::int32_t value=0;
    const auto r=std::from_chars(text.data(),text.data()+text.size(),value);
    if(text.empty() || r.ec!=std::errc{} || r.ptr!=text.data()+text.size() || value<0)
        throw CodecError("richonline_chance_event_number_invalid");
    return value;
}
void check_text(std::string_view text) {
    if(text.size()>4U*1024U*1024U || text.find('\0')!=text.npos)
        throw CodecError("richonline_chance_event_resource_invalid");
}
using Rows=std::vector<std::map<std::string,std::string,std::less<>>>;
Rows rows(std::string_view text,std::string_view section) {
    check_text(text); Rows result; bool selected=false;
    for(auto line:split(text,'\n')) {
        line=trim(line); if(line.empty() || line.starts_with("//") || line.front()==';') continue;
        if(line.front()=='[') { selected=line==section; if(selected) result.emplace_back(); continue; }
        if(!selected) continue;
        const auto at=line.find('='); if(at==line.npos) throw CodecError("richonline_chance_event_resource_invalid");
        if(!result.back().emplace(trim(line.substr(0,at)),trim(line.substr(at+1))).second)
            throw CodecError("richonline_chance_event_resource_invalid");
    }
    return result;
}
Bytes prefix(std::uint16_t game,const RichonlineChanceEvent& event,std::array<std::uint8_t,2> opaque) {
    Bytes result; append_le(result,0x4096,2); append_le(result,game,2);
    append_le(result,static_cast<std::uint16_t>(event.id),2);
    result.insert(result.end(),opaque.begin(),opaque.end()); return result;
}
void scalar_bounds(const RichonlineChanceEvent& event,std::int32_t value) {
    if(value<event.raw_parameters[0] || value>event.raw_parameters[1])
        throw CodecError("richonline_chance_event_policy_value_invalid");
}
void format_bounds(const RichonlineChanceEvent& event,std::string_view substitution,char kind) {
    std::size_t length=0, substitutions=0;
    for(std::size_t i=0;i<event.text.size();++i) {
        if(event.text[i]!='%') { ++length; continue; }
        if(++i==event.text.size()) throw CodecError("richonline_chance_event_format_invalid");
        if(event.text[i]=='%') ++length;
        else if(event.text[i]==kind) { ++substitutions; length+=substitution.size(); }
        else throw CodecError("richonline_chance_event_format_invalid");
    }
    if(substitutions!=1 || length>=128) throw CodecError("richonline_chance_event_presentation_overflow");
}
}

RichonlineChanceEventTable RichonlineChanceEventTable::parse(std::string_view news,
    std::string_view props,std::string_view strings) {
    check_text(news); RichonlineChanceEventTable result;
    for(auto line:split(news,'\n')) {
        line=trim(line); if(line.empty()) continue; const auto fields=split(line,'\t');
        if(fields.size()!=10 || fields[0].empty()) throw CodecError("richonline_chance_event_row_invalid");
        const auto category=number(fields[1]); auto& events=result.maps_[std::string(fields[0])];
        if(category>16 || events.size()>32767) throw CodecError("richonline_chance_event_row_invalid");
        events.push_back({static_cast<std::int16_t>(events.size()),static_cast<std::uint8_t>(category),
            {number(fields[2]),number(fields[3]),number(fields[4])},
            {number(fields[5]),number(fields[6])},std::string(fields[7]),std::string(fields[8]),std::string(fields[9])});
        if(events.back().raw_parameters[0]>events.back().raw_parameters[1])
            throw CodecError("richonline_chance_event_row_invalid");
    }
    if(result.maps_.empty()) throw CodecError("richonline_chance_event_row_invalid");
    for(const auto& row:rows(props,"[PROP]")) {
        if(!row.contains("indx") || !row.contains("name")) throw CodecError("richonline_chance_event_resource_invalid");
        const auto id=number(row.at("indx"));
        if(id>0 && id<=32767) result.names_.emplace(static_cast<std::int16_t>(id),row.at("name"));
    }
    for(const auto& row:rows(strings,"[ITEM]")) {
        if(!row.contains("indx") || !row.contains("string")) throw CodecError("richonline_chance_event_resource_invalid");
        result.strings_.emplace(number(row.at("indx")),row.at("string"));
    }
    return result;
}
RichonlineChanceEventTable RichonlineChanceEventTable::load(const std::filesystem::path& root) {
    const auto news=load_original_kpd(root/"Data"/"BwNews.kpd");
    const auto props=load_original_kpd(root/"Data"/"Prop.kpd");
    const auto strings=load_original_kpd(root/"Data"/"RichStr.kpd");
    const auto text=[](const Bytes& bytes) { return std::string_view(reinterpret_cast<const char*>(bytes.data()),bytes.size()); };
    return parse(text(news),text(props),text(strings));
}
const RichonlineChanceEvent& RichonlineChanceEventTable::event(std::string_view map,std::int32_t id) const {
    const auto found=maps_.find(map);
    if(found==maps_.end() || id<0 || static_cast<std::size_t>(id)>=found->second.size())
        throw CodecError("richonline_chance_event_identity_invalid");
    return found->second[static_cast<std::size_t>(id)];
}
std::size_t RichonlineChanceEventTable::size(std::string_view map) const {
    const auto found=maps_.find(map); return found==maps_.end() ? 0 : found->second.size();
}
std::string_view RichonlineChanceEventTable::card_name(std::int16_t id) const {
    const auto found=names_.find(id);
    if(found==names_.end()) throw CodecError("richonline_chance_event_card_name_missing");
    return found->second;
}
void RichonlineChanceEventTable::validate_scalar_presentation(std::string_view map,std::int32_t id,std::int32_t value) const {
    format_bounds(event(map,id),std::to_string(value),'d');
}
std::size_t RichonlineChanceEventTable::card_panel_bytes(std::span<const std::int16_t> cards,
    bool removing,bool inventory_full) const {
    const auto label=strings_.find(removing ? 28 : 24), full=strings_.find(154);
    if(label==strings_.end() || full==strings_.end()) throw CodecError("richonline_chance_event_strings_missing");
    std::size_t length=inventory_full ? full->second.size() : 0;
    for(const auto card:cards) {
        const auto name=names_.find(card);
        if(name==names_.end()) throw CodecError("richonline_chance_event_card_name_missing");
        length+=label->second.size()+name->second.size()+2;
    }
    if(length>=128) throw CodecError("richonline_chance_event_presentation_overflow");
    return length;
}
RichonlineChanceMoneyResult plan_richonline_chance_money(const RichonlineChanceEventTable& table,
    std::string_view map,std::int32_t id,std::uint16_t game,std::int32_t scalar,
    RichonlineChanceMoneyState before,std::array<std::uint8_t,2> opaque) {
    const auto& event=table.event(map,id);
    if(event.category>3) throw CodecError("richonline_chance_event_not_money");
    scalar_bounds(event,scalar); format_bounds(event,std::to_string(scalar),'d');
    const auto total=static_cast<std::int64_t>(before.cash)+before.deposit;
    if(before.cash<0 || before.deposit<0 || total>std::numeric_limits<std::int32_t>::max())
        throw CodecError("richonline_chance_event_balance_invalid");
    std::int32_t amount=scalar;
    if(event.category==1 || event.category==3) {
        const auto product=static_cast<std::int64_t>(scalar)*before.cash;
        if(scalar>100 || product>std::numeric_limits<std::int32_t>::max())
            throw CodecError("richonline_chance_event_percentage_overflow");
        amount=static_cast<std::int32_t>(static_cast<double>(static_cast<float>(product))/100.0);
    }
    auto after=before;
    if(event.category<=1) {
        const auto cash=static_cast<std::int64_t>(before.cash)-amount;
        after.cash=static_cast<std::int32_t>(std::max<std::int64_t>(0,cash));
        after.deposit=static_cast<std::int32_t>(std::max<std::int64_t>(0,before.deposit+std::min<std::int64_t>(0,cash)));
    } else {
        const auto cash=static_cast<std::int64_t>(before.cash)+amount;
        if(cash+before.deposit>std::numeric_limits<std::int32_t>::max()) throw CodecError("richonline_chance_event_balance_overflow");
        after.cash=static_cast<std::int32_t>(cash);
    }
    auto packet=prefix(game,event,opaque); append_le(packet,static_cast<std::uint32_t>(scalar),4);
    return {std::move(packet),after,event.category!=0 || total>amount,after.cash==0 && after.deposit==0};
}
RichonlineChanceCardsResult plan_richonline_chance_cards(const RichonlineChanceEventTable& table,
    const RichonlineChanceResources& resources,std::string_view map,std::int32_t id,std::uint16_t game,
    std::span<const std::int32_t> values,const RichonlineChanceInventory& before,std::array<std::uint8_t,2> opaque) {
    const auto& event=table.event(map,id);
    if(event.category<4 || event.category>6) throw CodecError("richonline_chance_event_not_cards");
    std::size_t occupied=0;
    for(const auto& slot:before) {
        if(slot.card_id==-1) {
            if(slot.count!=0) throw CodecError("richonline_chance_event_inventory_invalid");
        } else {
            if(slot.count<=0 || !resources.contains_card(slot.card_id))
                throw CodecError("richonline_chance_event_inventory_invalid");
            ++occupied;
        }
    }
    if(values.size()>8 || (event.category==5 && values.size()!=1) ||
        (event.category==4 && values.size()<static_cast<std::size_t>(event.raw_parameters[0])) ||
        (event.category==6 && values.size()<std::min(occupied,static_cast<std::size_t>(event.raw_parameters[0]))) ||
        (event.category!=5 && values.size()>static_cast<std::size_t>(event.raw_parameters[1])))
        throw CodecError("richonline_chance_event_card_count_invalid");
    auto after=before; std::vector<std::int16_t> cards; bool full=false; std::set<std::int32_t> removed;
    for(const auto value:values) {
        if(event.category==6) {
            if(value<0 || value>=8 || !removed.insert(value).second || after[static_cast<std::size_t>(value)].card_id<0 ||
                after[static_cast<std::size_t>(value)].count<=0) throw CodecError("richonline_chance_event_slot_invalid");
            auto& slot=after[static_cast<std::size_t>(value)]; cards.push_back(slot.card_id);
            if(--slot.count==0) slot={};
        } else {
            if(value<1 || value>32767) throw CodecError("richonline_chance_event_card_invalid");
            if(event.category==5) static_cast<void>(resources.single_card(map,id,value));
            const auto card=static_cast<std::int16_t>(value); cards.push_back(card);
            full=full || std::none_of(after.begin(),after.end(),[](const auto& slot){return slot.card_id==-1;});
            after=resources.add(map,card,1,after);
        }
    }
    static_cast<void>(table.card_panel_bytes(cards,event.category==6,full));
    if(event.category==5) {
        format_bounds(event,table.card_name(cards.front()),'s');
    } else format_bounds(event,std::to_string(values.size()),'d');
    auto packet=prefix(game,event,opaque);
    if(event.category!=5) append_le(packet,static_cast<std::uint32_t>(values.size()),4);
    for(const auto value:values) append_le(packet,static_cast<std::uint32_t>(value),4);
    return {std::move(packet),after};
}
}

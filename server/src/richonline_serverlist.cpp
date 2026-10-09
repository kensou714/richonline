#include "richonline_serverlist.hpp"
#include "credentials.hpp"
#include "original_options.hpp"
#include "../vendor/lzokay/lzokay.hpp"
#include <windows.h>
#include <algorithm>
#include <charconv>
#include <map>
#include <set>

namespace richnet {
namespace {
constexpr std::size_t max_labels=256,max_text=65536;
std::string_view trim(std::string_view text){const auto begin=text.find_first_not_of(" \t\r");return begin==text.npos?std::string_view{}:text.substr(begin,text.find_last_not_of(" \t\r")-begin+1);}
void validate_name(View name){
    if(name.empty()||name.size()>127)throw CodecError("serverlist_name_length_invalid");
    for(const auto c:name)if(c<32||c==127)throw CodecError("serverlist_name_control_invalid");
    if(MultiByteToWideChar(950,MB_ERR_INVALID_CHARS,reinterpret_cast<const char*>(name.data()),static_cast<int>(name.size()),nullptr,0)<=0)
        throw CodecError("serverlist_name_big5_invalid");
}
std::uint32_t number(std::string_view value){
    std::uint32_t result=0;const auto conversion=std::from_chars(value.data(),value.data()+value.size(),result);
    if(value.empty()||conversion.ec!=std::errc{}||conversion.ptr!=value.data()+value.size()||result>2147483647U)throw CodecError("serverlist_identifier_invalid");return result;
}
std::vector<RichonlineServerLabel> expected(const ChannelCatalog& channels,std::uint32_t server){
    if(channels.empty()||channels.size()>max_labels||server>2147483647U)throw CodecError("serverlist_catalog_invalid");
    std::vector<RichonlineServerLabel> labels;std::set<std::uint32_t> keys;
    for(const auto& channel:channels){
        if(channel.key>2147483647U||!keys.insert(channel.key).second)throw CodecError("serverlist_channel_duplicate_or_invalid");
        auto name=client_text(channel.name_utf8,ClientProfile::richonline);validate_name(name);labels.push_back({server,channel.key,std::move(name)});
    }
    return labels;
}
}
std::vector<RichonlineServerLabel> parse_richonline_serverlist(View bytes){
    if(bytes.empty()||bytes.size()>max_text||std::find(bytes.begin(),bytes.end(),0)!=bytes.end())throw CodecError("serverlist_text_invalid");
    std::string_view text(reinterpret_cast<const char*>(bytes.data()),bytes.size());
    std::vector<RichonlineServerLabel> labels;std::map<std::string,std::string> fields;std::set<std::pair<std::uint32_t,std::uint32_t>> keys;
    bool section=false;
    const auto finish=[&]{
        if(!section)return;
        if(fields.size()!=3||!fields.contains("serverid")||!fields.contains("channelid")||!fields.contains("name"))throw CodecError("serverlist_fields_invalid");
        const auto server=number(fields.at("serverid")),channel=number(fields.at("channelid"));
        if(!keys.emplace(server,channel).second)throw CodecError("serverlist_pair_duplicate");
        const auto& name=fields.at("name");Bytes encoded(name.begin(),name.end());validate_name(encoded);
        labels.push_back({server,channel,std::move(encoded)});if(labels.size()>max_labels)throw CodecError("serverlist_capacity_exceeded");fields.clear();
    };
    while(!text.empty()){
        const auto end=text.find('\n');const auto line=trim(text.substr(0,end));text=end==text.npos?std::string_view{}:text.substr(end+1);
        if(line.empty()||line.starts_with("//")||line.front()==';'||line.front()=='#')continue;
        if(line.front()=='['){finish();if(line!="[LOBBY]")throw CodecError("serverlist_section_invalid");section=true;continue;}
        if(!section)throw CodecError("serverlist_missing_section");const auto equals=line.find('=');
        if(equals==line.npos||!fields.emplace(trim(line.substr(0,equals)),trim(line.substr(equals+1))).second)throw CodecError("serverlist_field_duplicate_or_invalid");
    }
    finish();if(labels.empty())throw CodecError("serverlist_empty");return labels;
}
std::vector<RichonlineServerLabel> decode_richonline_serverlist(View packed){return parse_richonline_serverlist(decode_original_kpd(packed,max_text));}
Bytes encode_richonline_serverlist(const ChannelCatalog& channels,std::uint32_t server,std::uint8_t additive){
    const auto labels=expected(channels,server);std::string text;
    for(const auto& label:labels){text+="[LOBBY]\r\nserverid = "+std::to_string(label.server_id)+"\r\nchannelid = "+std::to_string(label.channel_id)+"\r\nname = ";text.append(reinterpret_cast<const char*>(label.name_big5.data()),label.name_big5.size());text+="\r\n\r\n";}
    if(text.size()>max_text)throw CodecError("serverlist_text_too_large");
    Bytes compressed(lzokay::compress_worst_size(text.size()));std::size_t size=0;
    if(lzokay::compress(reinterpret_cast<const std::uint8_t*>(text.data()),text.size(),compressed.data(),compressed.size(),size)!=lzokay::EResult::Success)throw CodecError("serverlist_compression_failed");
    compressed.resize(size);Bytes packed{additive};append_le(packed,static_cast<std::uint32_t>(text.size()),4);append_le(packed,static_cast<std::uint32_t>(size),4);packed.insert(packed.end(),compressed.begin(),compressed.end());
    for(std::size_t i=1;i<packed.size();++i)packed[i]=static_cast<std::uint8_t>(packed[i]+additive);
    validate_richonline_serverlist(packed,channels,server);return packed;
}
void validate_richonline_serverlist(View packed,const ChannelCatalog& channels,std::uint32_t server){
    auto actual=decode_richonline_serverlist(packed),wanted=expected(channels,server);
    const auto less=[](const auto& a,const auto& b){return std::pair{a.server_id,a.channel_id}<std::pair{b.server_id,b.channel_id};};
    std::sort(actual.begin(),actual.end(),less);std::sort(wanted.begin(),wanted.end(),less);
    if(actual!=wanted)throw CodecError("serverlist_catalog_mismatch");
}
}

#include "richonline_levels.hpp"
#include "original_options.hpp"

#include <charconv>
#include <map>
#include <string>

namespace richnet {
namespace {
std::string_view trim(std::string_view value) {
    const auto first=value.find_first_not_of(" \t\r");
    return first==value.npos?std::string_view{}:value.substr(first,value.find_last_not_of(" \t\r")-first+1);
}
std::uint32_t number(std::string_view text) {
    std::uint32_t value{};const auto result=std::from_chars(text.data(),text.data()+text.size(),value);
    if(result.ec!=std::errc{} || result.ptr!=text.data()+text.size() || value>2147483647U)
        throw CodecError("richonline_level_number_invalid");
    return value;
}
}
RichonlineLevelThresholds parse_richonline_level_thresholds(std::string_view decoded) {
    if(decoded.size()>1024*1024 || decoded.find('\0')!=decoded.npos)throw CodecError("richonline_level_table_invalid");
    std::map<std::string,std::map<std::string,std::string,std::less<>>,std::less<>> sections;
    std::string section;
    while(!decoded.empty()) {
        const auto end=decoded.find('\n');const auto line=trim(decoded.substr(0,end));
        decoded=end==decoded.npos?std::string_view{}:decoded.substr(end+1);
        if(line.empty() || line.starts_with("//") || line.front()==';')continue;
        if(line.size()>4096)throw CodecError("richonline_level_line_too_large");
        if(line.front()=='[') {
            if(!line.ends_with(']') || line.size()<3)throw CodecError("richonline_level_section_invalid");
            section=std::string(trim(line.substr(1,line.size()-2)));
            if(!sections.emplace(section,std::map<std::string,std::string,std::less<>>{}).second)
                throw CodecError("richonline_level_duplicate_section");
        } else {
            const auto split=line.find('=');
            if(section.empty() || split==line.npos || trim(line.substr(0,split)).empty())
                throw CodecError("richonline_level_line_invalid");
            if(!sections.at(section).emplace(trim(line.substr(0,split)),trim(line.substr(split+1))).second)
                throw CodecError("richonline_level_duplicate_field");
        }
    }
    auto get=[&](const std::string& name,const char* key) {
        const auto found=sections.find(name);
        if(found==sections.end() || !found->second.contains(key))throw CodecError("richonline_level_missing_field");
        return number(found->second.at(key));
    };
    if(get("all","num")!=21 || sections.size()!=22)throw CodecError("richonline_level_count_invalid");
    RichonlineLevelThresholds result{};
    for(std::size_t i=0;i<result.size();++i) {
        result[i]=get("level"+std::to_string(i),"exp");
        if((i==0 && result[i]!=0) || (i>0 && result[i]<=result[i-1]))throw CodecError("richonline_level_threshold_invalid");
    }
    return result;
}
RichonlineLevelThresholds load_richonline_level_thresholds(const std::filesystem::path& client_root) {
    const auto bytes=load_original_kpd(client_root/"Data"/"Level.kpd",1024*1024);
    return parse_richonline_level_thresholds(std::string_view(reinterpret_cast<const char*>(bytes.data()),bytes.size()));
}
}

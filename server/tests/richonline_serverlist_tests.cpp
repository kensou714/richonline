#include "richonline_serverlist.hpp"
#include "credentials.hpp"
#include <fstream>
#include <filesystem>
#include <iostream>
#include <windows.h>
#include <utility>

namespace {
using namespace richnet;
void check(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
template<class F>void rejected(F action){bool failed=false;try{action();}catch(const CodecError&){failed=true;}check(failed,"invalid serverlist accepted");}
Bytes text(std::string_view value){return {value.begin(),value.end()};}
std::filesystem::path resource_path(){
    const auto library=LoadLibraryW(L"shell32.dll");check(library!=nullptr,"load_shell32");
    using ParseCommandLine=LPWSTR* (WINAPI*)(LPCWSTR,int*);
    const auto parse=reinterpret_cast<ParseCommandLine>(GetProcAddress(library,"CommandLineToArgvW"));
    if(!parse){FreeLibrary(library);throw std::runtime_error("command_line_parser_missing");}
    int count=0;auto arguments=parse(GetCommandLineW(),&count);
    if(!arguments){FreeLibrary(library);throw std::runtime_error("command_line_parse_failed");}
    const std::filesystem::path result=count>1?arguments[1]:L"";
    LocalFree(arguments);FreeLibrary(library);return result;
}
}
int main(int argc,char**){try{
    using namespace richnet;
    ChannelCatalog catalog;
    for(const auto& name:{"休閒大廳","BOSS挑戰","自由對戰"}){ChannelCatalogEntry entry{};entry.key=static_cast<std::uint32_t>(catalog.size());entry.name_utf8=name;catalog.push_back(entry);}
    for(const auto additive:{0U,1U,127U,255U}){
        const auto packed=encode_richonline_serverlist(catalog,1,static_cast<std::uint8_t>(additive));const auto labels=decode_richonline_serverlist(packed);
        check(labels.size()==3,"three labels absent");for(std::size_t i=0;i<labels.size();++i)check(labels[i].server_id==1&&labels[i].channel_id==i&&labels[i].name_big5==client_text(catalog[i].name_utf8),"label does not match actual channel");
        validate_richonline_serverlist(packed,catalog,1);rejected([&]{validate_richonline_serverlist(packed,catalog,2);});
        auto truncated=packed;truncated.pop_back();rejected([&]{decode_richonline_serverlist(truncated);});
    }
    for(const auto& value:{"[LOBBY]\nserverid=1\nchannelid=0\n", "[LOBBY]\nserverid=1\nchannelid=0\nname=x\nserverid=2\n",
        "[LOBBY]\nserverid=1\nchannelid=0\nname=x\n[LOBBY]\nserverid=1\nchannelid=0\nname=y\n"})rejected([&]{parse_richonline_serverlist(text(value));});
    auto invalid=catalog;invalid[1].key=0;rejected([&]{encode_richonline_serverlist(invalid,1,1);});
    invalid=catalog;invalid[1].name_utf8="bad\n[LOBBY]";rejected([&]{encode_richonline_serverlist(invalid,1,1);});
    if(argc==2){
        std::ifstream input(resource_path(),std::ios::binary);check(static_cast<bool>(input),"shipped resource missing");Bytes bytes((std::istreambuf_iterator<char>(input)),{});
        const auto labels=decode_richonline_serverlist(bytes);
        constexpr std::array<std::pair<std::uint32_t,std::uint32_t>,20> original_pairs{{
            {1,0},{1,1},{1,2},{1,3},{1,4},{6,0},{6,1},{7,0},{7,1},{8,0},{8,1},
            {9,0},{9,1},{10,0},{10,1},{11,0},{11,1},{11,2},{11,3},{11,4}}};
        if(labels.size()!=original_pairs.size()){std::string detail="shipped label count changed; actual="+std::to_string(labels.size());for(const auto& label:labels)detail+=" ("+std::to_string(label.server_id)+","+std::to_string(label.channel_id)+")";throw std::runtime_error(detail);}
        for(std::size_t i=0;i<labels.size();++i)check(std::pair{labels[i].server_id,labels[i].channel_id}==original_pairs[i],"shipped pair mismatch");
    }
    std::cout<<"PASS NEW Serverlist actual three-channel labels, KPD roundtrip, malformed/resource mismatch rejection\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}

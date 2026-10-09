#include "richonline_levels.hpp"
#include <iostream>
#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#endif

namespace {
void check(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
template<class F>void rejected(F fn){try{fn();}catch(const richnet::CodecError&){return;}throw std::runtime_error("missing_rejection");}
std::filesystem::path resource_root(int argc,char** argv){
#ifdef _WIN32
    (void)argc;(void)argv;
    // Read the Unicode command line directly: CRT argv is not UTF-8 on Windows.
    const auto library=LoadLibraryW(L"shell32.dll");
    check(library!=nullptr,"load_shell32");
    using ParseCommandLine=LPWSTR* (WINAPI*)(LPCWSTR,int*);
    const auto parse=reinterpret_cast<ParseCommandLine>(GetProcAddress(library,"CommandLineToArgvW"));
    if(!parse){FreeLibrary(library);throw std::runtime_error("command_line_parser_missing");}
    int count=0;auto arguments=parse(GetCommandLineW(),&count);
    if(!arguments){FreeLibrary(library);throw std::runtime_error("command_line_parse_failed");}
    const std::filesystem::path result=count>1?arguments[1]:L"../Richonline";
    LocalFree(arguments);FreeLibrary(library);return result;
#else
    return argc>1?std::filesystem::path(argv[1]):std::filesystem::path("../Richonline");
#endif
}
}
int main(int argc,char** argv){try{
    using namespace richnet;
    std::string text="[all]\nnum=21\n";
    for(int i=0;i<21;++i)text+="[level"+std::to_string(i)+"]\nexp="+std::to_string(i*50)+"\n";
    check(parse_richonline_level_thresholds(text)[20]==1000,"fixture_threshold");
    rejected([&]{(void)parse_richonline_level_thresholds(text+"[level1]\nexp=999\n");});
    auto bad=text;bad.replace(bad.find("exp=50\n"),7,"exp=0\n");
    rejected([&]{(void)parse_richonline_level_thresholds(bad);});
    bad=text;bad.replace(bad.find("num=21"),6,"num=20");
    rejected([&]{(void)parse_richonline_level_thresholds(bad);});
    const auto root=resource_root(argc,argv);
    const auto actual=load_richonline_level_thresholds(root);
    check(actual[0]==0 && actual[1]==50 && actual[2]==120 && actual[3]==200 && actual[6]==700,"actual_level_thresholds");
    std::cout<<"PASS Level.kpd cumulative thresholds; maximum="<<actual[20]<<'\n';
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}

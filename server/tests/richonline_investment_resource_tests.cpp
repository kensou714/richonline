#include "richonline_investment.hpp"
#include "original_options.hpp"

#include <algorithm>
#include <iostream>

namespace {
using namespace richnet;
void check(bool ok,const char* message) { if(!ok) throw std::runtime_error(message); }
template<class F> void rejects(F action,const char* code) {
    try { action(); } catch(const CodecError& e) { check(std::string(e.what())==code,e.what()); return; }
    throw std::runtime_error("expected_investment_resource_rejection");
}
std::string record(const std::filesystem::path& root) {
    const auto bytes=load_original_kpd(root/"Data/BossWar.kpd");
    std::string text(bytes.begin(),bytes.end());
    std::erase_if(text,[](char value){return value==' ' || value=='\t' || value=='\r';});
    const auto identity=text.find("mapName=BS_1_1.emp\n");
    check(identity!=text.npos,"actual_bosswar_identity_missing");
    const auto start=text.rfind("[MAP]",identity),end=text.find("[MAP]",identity);
    text=text.substr(start,end==text.npos ? std::string::npos : end-start);
    for(const auto& key:{std::string{"investBase="},std::string{"investReturn="}}) {
        const auto at=text.find(key);
        if(at==text.npos) continue;
        const auto last=text.find('\n',at); text.erase(at,last==text.npos ? text.size()-at : last-at+1);
    }
    return text;
}
void put_static(OriginalEmp& map,std::int16_t position,std::uint8_t type) {
    map.payload.at(map.tile_types_offset+4U*static_cast<std::size_t>(position))=type;
}
void resource_values_and_missing_fields(const std::filesystem::path& root) {
    const auto source=record(root);
    auto emp=load_original_emp(root/"Map/BS_1_1.emp");
    const auto original=richonline_road_topology(emp);
    std::vector<std::int16_t> roads;
    for(const auto& cell:original.cells()) if(cell.walkable) roads.push_back(cell.position);
    check(roads.size()>=10,"actual_map_has_too_few_roads");
    // Keep actual NEW metadata/layout, changing two walkable event cells only.
    put_static(emp,roads[0],67); put_static(emp,roads[1],67);
    const auto topology=richonline_road_topology(emp);
    const auto stage=parse_richonline_boss_stage(source+"\ninvestBase=321\ninvestReturn=7654\n","BS_1_1.emp",emp);
    check(stage.invest_base==321 && stage.invest_return==7654,"investment_resource_keys_not_parsed");
    const auto rules=make_richonline_investment_rules(topology,stage);
    check(rules.invest_base==321 && rules.invest_return==7654 &&
        rules.positions==std::vector<std::int16_t>{roads[0],roads[1]},"investment_rules_not_map_selected");
    const auto missing=parse_richonline_boss_stage(source,"BS_1_1.emp",emp);
    check(!missing.invest_base && !missing.invest_return,"missing_resource_fields_replaced_with_zero");
    rejects([&]{make_richonline_investment_rules(topology,missing);},"richonline_investment_resource_fields_missing");
    const auto zero=parse_richonline_boss_stage(source+"\ninvestBase=0\ninvestReturn=0\n","BS_1_1.emp",emp);
    check(zero.invest_base && *zero.invest_base==0 && zero.invest_return && *zero.invest_return==0,
        "present_resource_zero_confused_with_missing");
    const auto zero_rules=make_richonline_investment_rules(topology,zero);
    check(zero_rules.invest_base==0 && zero_rules.invest_return==0,"zero_resource_fee_or_reward_invented");
    auto mismatch=stage; ++mismatch.width;
    rejects([&]{make_richonline_investment_rules(topology,mismatch);},"richonline_investment_map_metadata_mismatch");
    for(const auto& key:{std::string{"investBase"},std::string{"investReturn"}}) {
        const auto negative="richonline_stage_range:"+key;
        rejects([&]{parse_richonline_boss_stage(source+"\n"+key+"=-1\n","BS_1_1.emp",emp);},negative.c_str());
        const auto overflow="richonline_stage_number:"+key;
        rejects([&]{parse_richonline_boss_stage(source+"\n"+key+"=2147483648\n","BS_1_1.emp",emp);},overflow.c_str());
    }
    for(std::size_t i=0;i<10;++i) put_static(emp,roads[i],67);
    rejects([&]{make_richonline_investment_rules(richonline_road_topology(emp),1,1);},"richonline_investment_point_limit");
}
void real_client_maps(const std::filesystem::path& root) {
    for(unsigned index=1;index<=4;++index) {
        const auto name="BS_1_"+std::to_string(index)+".emp";
        const auto stage=load_richonline_boss_stage(root,name);
        const auto topology=load_richonline_road_topology(root/"Map"/name);
        const auto rules=make_richonline_investment_rules(topology,stage);
        check(rules.positions.size()<=9,"real_map_exceeds_client_collection_storage");
        std::cout<<name<<" investment_points="<<rules.positions.size()<<" investBase=";
        if(stage.invest_base) std::cout<<*stage.invest_base; else std::cout<<"absent";
        std::cout<<" investReturn=";
        if(stage.invest_return) std::cout<<*stage.invest_return; else std::cout<<"absent";
        std::cout<<'\n';
    }
    const auto zhao=load_richonline_boss_stage(root,"V_BS_1_1.emp",2);
    const auto topology=load_richonline_road_topology(root/"Map/V_BS_1_1.emp");
    const auto rules=make_richonline_investment_rules(topology,zhao);
    check(rules.positions.size()<=9,"special_map_exceeds_client_collection_storage");
}
}
int main(int argc,char** argv) {
    if(argc!=2) return 2;
    try {
        const auto root=std::filesystem::path(argv[1]);
        resource_values_and_missing_fields(root); real_client_maps(root);
        std::cout<<"PASS NEW investment actual resource keys, missing fields and map bounds\n";
    } catch(const std::exception& e) { std::cerr<<"FAIL "<<e.what()<<'\n'; return 1; }
}

#include "richonline_boss_property.hpp"
#include "richonline_boss_stage.hpp"
#include "original_map.hpp"
#include "../vendor/lzokay/lzokay.hpp"
#include <fstream>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason) { if (!value) throw std::runtime_error(reason); }
RichonlineLandingContext landing(std::int16_t position = 232) { return {1,position,33,216,3,true,2,false}; }
void affordable_buy(const std::filesystem::path& root,std::uint32_t cash) {
    RichonlineBossProperty properties(root,0xabcd,{98765,cash},load_richonline_boss_stage(root,"BS_1_1.emp"));
    check(properties.price(216) == 100 && !properties.owner(216),"real_initial_property_wrong");
    const auto result = properties.land(landing());
    check(result && result->progress == RichonlineLandingProgress::complete && result->messages == std::vector<Bytes>{
        {0x13,0x40,0xcd,0xab,232,0},{0x20,0x40,0xcd,0xab,1}},"purchase_wire_wrong");
    check(properties.cash() == std::array<std::uint32_t,2>{98765,cash-100} && properties.owner(216) == 1,"purchase_ledger_wrong");
    const auto revisit=properties.land(landing(231));
    check(revisit && revisit->messages.back()==Bytes({0x3d,0x40,0xcd,0xab,11}) &&
        properties.cash()[1] == cash-100,"repeat_landing_rebought_same_property");
}
void boss_owned_empty_land_builds_instead_of_disconnect(const std::filesystem::path& root) {
    RichonlineBossProperty properties(root,0x1234,{20000,100000},load_richonline_boss_stage(root,"BS_1_1.emp"));
    properties.land(landing(232));
    const auto built=properties.land(landing(231));
    check(built && built->progress==RichonlineLandingProgress::complete && built->messages==std::vector<Bytes>{
        {0x13,0x40,0x34,0x12,231,0},{0x3d,0x40,0x34,0x12,11}},"owned_boss_property_did_not_build_and_resume");
    check(properties.owner(216)==1 && properties.cash()[1]==99900,"first_construction_changed_owner_or_cash");
}
void no_wait_when_insufficient(const std::filesystem::path& root,std::uint32_t cash) {
    RichonlineBossProperty properties(root,0x1234,{98765,cash},load_richonline_boss_stage(root,"BS_1_1.emp"));
    const auto result = properties.land(landing(231));
    check(result && result->progress == RichonlineLandingProgress::complete && result->messages == std::vector<Bytes>{
        {0x13,0x40,0x34,0x12,231,0}},"insufficient_cash_sent_purchase_response");
    check(properties.cash()[1] == cash && !properties.owner(216),"insufficient_cash_mutated_ledger");
}
void unsupported_preserves_ledger(const std::filesystem::path& root) {
    RichonlineBossProperty properties(root,8,{1234,100000},load_richonline_boss_stage(root,"BS_1_1.emp"));
    std::vector<RichonlineLandingContext> invalid;
    auto c = landing(); c.actor_slot = 0; c.synthetic_actor = false; invalid.push_back(c);
    c = landing(); c.game_mode = 0; invalid.push_back(c);
    c = landing(); c.synthetic_actor = false; invalid.push_back(c);
    c = landing(); c.road_degree = 3; invalid.push_back(c);
    c = landing(); c.occupied_by_other_actor = true; invalid.push_back(c);
    c = landing(); c.position = 0; invalid.push_back(c);
    c = landing(); c.property_ref = 217; invalid.push_back(c);
    c = landing(); c.static_type = 10; invalid.push_back(c);
    for (const auto& context : invalid) check(!properties.land(context),"unsupported_context_handled");
    check(properties.cash() == std::array<std::uint32_t,2>{1234,100000} && !properties.owner(216),"unsupported_context_mutated_ledger");
    check(!properties.price(217),"unaudited_property_exposed");
}
void human_decisions_and_timeout(const std::filesystem::path& root) {
    auto now = RichonlineBossProperty::Clock::time_point{};
    for (const bool buy : {false,true}) {
        RichonlineBossProperty properties(root,0x1234,{20000,100000},load_richonline_boss_stage(root,"BS_1_1.emp"));
        properties.enable_human_decisions(std::chrono::milliseconds{5000},[&] { return now; });
        auto ctx = landing(); ctx.actor_slot=0; ctx.synthetic_actor=false;
        const auto offered = properties.land(ctx);
        check(offered && offered->progress==RichonlineLandingProgress::await_event && offered->messages.size()==1,"human_purchase_not_pending");
        const Bytes request{0x20,0,7,0,0,0,0,0,static_cast<std::uint8_t>(buy),0xaa,0xbb,0xcc};
        const auto completed=properties.decide(request);
        check(completed.progress==RichonlineLandingProgress::complete && completed.messages==std::vector<Bytes>{{0x20,0x40,0x34,0x12,static_cast<std::uint8_t>(buy)}},"human_purchase_response_wrong");
        check(properties.cash()[0]==(buy ? 19900U : 20000U) && properties.owner(216)==(buy ? std::optional<std::uint8_t>{0} : std::nullopt),"human_purchase_ledger_wrong");
        try { properties.decide(request); throw std::runtime_error("duplicate_purchase_accepted"); }
        catch(const CodecError& e) { check(std::string(e.what())=="richonline_property_no_pending_decision","wrong_duplicate_error"); }
    }
    RichonlineBossProperty properties(root,0x1234,{20000,100000},load_richonline_boss_stage(root,"BS_1_1.emp"));
    properties.enable_human_decisions(std::chrono::milliseconds{5000},[&] { return now; });
    auto ctx=landing(); ctx.actor_slot=0; ctx.synthetic_actor=false;
    properties.land(ctx);
    now+=std::chrono::milliseconds{4999}; check(!properties.poll(),"purchase_expired_early");
    now+=std::chrono::milliseconds{1}; const auto expired=properties.poll();
    check(expired && expired->messages==std::vector<Bytes>{{0x20,0x40,0x34,0x12,0}} && !properties.owner(216) && properties.cash()[0]==20000,"timeout_did_not_decline");
    check(!properties.poll(),"timeout_repeated");
    RichonlineBossProperty late(root,0x1234,{20000,100000},load_richonline_boss_stage(root,"BS_1_1.emp"));
    late.enable_human_decisions(std::chrono::milliseconds{5000},[&] { return now; });
    late.land(ctx); now+=std::chrono::milliseconds{5000};
    const auto decline=late.decide(Bytes{0x20,0,7,0,0,0,0,0,1,1,2,3});
    check(decline.messages[0].back()==0 && late.cash()[0]==20000 && !late.owner(216),"expired_click_bought_property");
    for (const auto cash : {99U,100U}) {
        RichonlineBossProperty poor(root,0x1234,{cash,100000},load_richonline_boss_stage(root,"BS_1_1.emp"));
        poor.enable_human_decisions(std::chrono::milliseconds{5000},[&] { return now; });
        const auto outcome=poor.land(ctx);
        check(outcome && outcome->progress==RichonlineLandingProgress::complete && outcome->messages.size()==1 && !poor.poll(),"insufficient_human_waited_for_purchase");
    }
}
void ordinary_properties_share_decisions_but_not_ownership(const std::filesystem::path& root) {
    auto now=RichonlineBossProperty::Clock::time_point{};
    const auto topology=load_richonline_road_topology(root/"Map"/"BS_1_1.emp");
    RichonlineBossProperty properties(root,0x1234,{20000,100000},load_richonline_boss_stage(root,"BS_1_1.emp"));
    properties.enable_human_decisions(std::chrono::milliseconds{5000},[&] { return now; });
    for (const auto position : {119,146,157,231}) {
        const auto& cell=topology.cell(static_cast<std::int16_t>(position));
        RichonlineLandingContext ctx{0,static_cast<std::int16_t>(position),cell.static_type,cell.property_ref,3,false,2,false};
        check(properties.price(cell.property_ref)==100 && !properties.owner(cell.property_ref),"ordinary_resource_property_missing");
        const auto offered=properties.land(ctx);
        check(offered && offered->progress==RichonlineLandingProgress::await_event && offered->pending_opcode==0x20,"ordinary_human_purchase_not_pending");
        const auto bought=properties.decide(Bytes{0x20,0,7,0,0,0,0,0,1,0xaa,0xbb,0xcc});
        check(bought.messages==std::vector<Bytes>{{0x20,0x40,0x34,0x12,1}} && properties.owner(cell.property_ref)==0,"ordinary_property_purchase_wrong");
    }
    check(properties.cash()[0]==19600 && properties.price(168)==100 && !properties.owner(168) &&
        properties.building(168)==RichonlineBossProperty::Building{13,1},"ordinary_property_scope_or_total_wrong");
    for (const auto position : {120,162,173,232}) {
        const auto& cell=topology.cell(static_cast<std::int16_t>(position));
        const auto revisit=properties.land({0,static_cast<std::int16_t>(position),cell.static_type,cell.property_ref,3,false,2,false});
        check(revisit && revisit->pending_opcode==0x37,"sibling_road_did_not_offer_construction");
        properties.decide(Bytes{0x37,0,7,0,10,0});
        check(properties.cash()[0]==19600,"sibling_road_bought_property_twice");
    }
    for (const auto position : {120,162,173}) {
        const auto& cell=topology.cell(static_cast<std::int16_t>(position));
        for (const auto cash : {100U,101U}) {
            RichonlineBossProperty boss(root,0x1234,{20000,cash},load_richonline_boss_stage(root,"BS_1_1.emp"));
            const auto result=boss.land({1,static_cast<std::int16_t>(position),cell.static_type,cell.property_ref,3,true,2,false});
            check(result && result->progress==RichonlineLandingProgress::complete && result->messages.size()==(cash>100 ? 2U : 1U),"ordinary_boss_affordability_wrong");
            check(boss.cash()[1]==(cash>100 ? 1U : cash) && boss.owner(cell.property_ref)==(cash>100 ? std::optional<std::uint8_t>{1} : std::nullopt),"ordinary_boss_ledger_wrong");
        }
    }
    for (const bool timeout : {false,true}) {
        RichonlineBossProperty decline(root,0x1234,{20000,100000},load_richonline_boss_stage(root,"BS_1_1.emp"));
        decline.enable_human_decisions(std::chrono::milliseconds{5000},[&] { return now; });
        check(decline.land({0,162,36,164,3,false,2,false}).has_value(),"actual162_purchase_missing");
        if (timeout) {
            now+=std::chrono::milliseconds{5000};
            const auto result=decline.poll();
            check(result && result->messages==std::vector<Bytes>{{0x20,0x40,0x34,0x12,0}},"actual162_timeout_wrong");
        } else check(decline.decide(Bytes{0x20,0,7,0,0,0,0,0,0,1,2,3}).messages[0].back()==0,"actual162_decline_wrong");
        check(!decline.owner(164) && decline.cash()[0]==20000,"actual162_decline_mutated_ledger");
    }
}
void prices_are_projected_from_each_resource_record(const std::filesystem::path& root) {
    const auto fixture=std::filesystem::temp_directory_path()/
        ("richonline-property-prices-"+std::to_string(RichonlineBossProperty::Clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(fixture/"Map");
    std::filesystem::create_directories(fixture/"Data");
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() { std::error_code error; std::filesystem::remove_all(path,error); }
    } cleanup{fixture};
    std::filesystem::copy_file(root/"Data"/"Option.kpd",fixture/"Data"/"Option.kpd");
    std::filesystem::copy_file(root/"Data"/"Build.kpd",fixture/"Data"/"Build.kpd");
    std::filesystem::copy_file(root/"Data"/"BossWar.kpd",fixture/"Data"/"BossWar.kpd");
    std::filesystem::copy_file(root/"Data"/"BwbValue.kpd",fixture/"Data"/"BwbValue.kpd");
    auto emp=load_original_emp(root/"Map"/"BS_1_1.emp");
    const auto offset=emp.property_offset+164U*88U+56U;
    emp.payload.at(offset)=17;
    Bytes compressed(lzokay::compress_worst_size(emp.payload.size()));
    std::size_t compressed_size=0;
    check(lzokay::compress(emp.payload.data(),emp.payload.size(),compressed.data(),compressed.size(),compressed_size)==lzokay::EResult::Success,"fixture_compression_failed");
    Bytes file=emp.header;
    file.push_back(0);
    append_le(file,static_cast<std::uint32_t>(emp.payload.size()),4);
    append_le(file,static_cast<std::uint32_t>(compressed_size),4);
    file.insert(file.end(),compressed.begin(),compressed.begin()+static_cast<std::ptrdiff_t>(compressed_size));
    {
        std::ofstream output(fixture/"Map"/"BS_1_1.emp",std::ios::binary);
        output.write(reinterpret_cast<const char*>(file.data()),static_cast<std::streamsize>(file.size()));
        check(static_cast<bool>(output),"fixture_write_failed");
    }
    RichonlineBossProperty properties(fixture,0x1234,{20000,100000},load_richonline_boss_stage(fixture,"BS_1_1.emp"));
    check(properties.price(164)==170 && properties.price(104)==100,"resource_price_was_hardcoded_or_shared");
    check(properties.land({1,162,36,164,3,true,2,false}).has_value() && properties.cash()[1]==99830,"changed_resource_price_not_charged");
    const auto stage=load_richonline_boss_stage(fixture,"BS_1_1.emp");
    RichonlineBossProperty selected(fixture,0x1234,{20000,100000},stage);
    check(selected.price(164)==170 && selected.price(104)==100,"stage_property_price_was_hardcoded");
    check(selected.land({1,162,36,164,3,true,2,false}).has_value() && selected.cash()[1]==99830,
        "stage_property_changed_price_not_charged");
}
RichonlineLandingContext selected_landing(const RichonlineRoadTopology& topology,std::int16_t position) {
    const auto& cell=topology.cell(position);
    std::uint8_t degree=0;
    for (const auto& neighbor : cell.neighbors) if (neighbor) ++degree;
    return {1,position,cell.static_type,cell.property_ref,3,true,degree,false};
}
void selected_map_properties_and_building_caps(const std::filesystem::path& root) {
    for (const auto category : {0U,2U}) {
        const auto name=category==2 ? "V_BS_1_1.emp" : "BS_1_1.emp";
        const auto stage=load_richonline_boss_stage(root,name,category);
        const auto topology=load_richonline_road_topology(root/"Map"/name);
        RichonlineBossProperty properties(root,0x1234,{20000,100000},stage);
        const auto position=static_cast<std::int16_t>(category==2 ? 114 : 232);
        const auto context=selected_landing(topology,position);
        const auto ref=context.property_ref;
        const auto purchase=properties.land(context);
        check(purchase && purchase->messages.back()==Bytes({0x20,0x40,0x34,0x12,1}) &&
            properties.owner(ref)==1 && properties.cash()[1]==99900,"selected_map_purchase_wrong");
        const std::uint8_t cap=category==2 ? 6 : 5;
        for (std::uint8_t level=1;level<=cap;++level) {
            const auto outcome=properties.land(context);
            const auto building=properties.building(ref);
            check(outcome && outcome->messages.size()==2 && building && building->kind==11 && building->level==level,
                "selected_map_construction_cap_wrong");
        }
        const auto capped=properties.land(context);
        check(capped && capped->messages.size()==1 && properties.building(ref)->level==cap && properties.cash()[1]==99900,
            "selected_map_maximum_building_did_not_complete");
    }
}
void special_map_prebuilt_properties_preserve_initial_state(const std::filesystem::path& root) {
    const auto stage=load_richonline_boss_stage(root,"V_BS_1_1.emp",2);
    const auto topology=load_richonline_road_topology(root/"Map"/stage.map_name);
    RichonlineBossProperty properties(root,0x1234,{12000,150000},stage);
    for (const auto ref : {132,139,212,219})
        check(properties.price(static_cast<std::int16_t>(ref))==100,"special_map_empty_property_missing");
    for (const auto position : {168,169,165,166}) {
        const auto context=selected_landing(topology,static_cast<std::int16_t>(position));
        const auto kind=context.property_ref==153 ? std::int8_t{13} : std::int8_t{16};
        check(properties.price(context.property_ref)==600 && !properties.owner(context.property_ref) &&
            properties.building(context.property_ref)==RichonlineBossProperty::Building{kind,3},
            "special_prebuilt_resource_state_lost");
    }
    check(properties.cash()==std::array<std::uint32_t,2>{12000,150000},"initialization_charged_prebuilt_property");
}
}
int main(int argc,char** argv) {
    try {
        check(argc == 2,"resource_path_required"); const std::filesystem::path root(argv[1]);
        boss_owned_empty_land_builds_instead_of_disconnect(root);
        affordable_buy(root,100000); affordable_buy(root,101);
        no_wait_when_insufficient(root,100); no_wait_when_insufficient(root,99);
        unsupported_preserves_ledger(root);
        human_decisions_and_timeout(root);
        ordinary_properties_share_decisions_but_not_ownership(root);
        prices_are_projected_from_each_resource_record(root);
        selected_map_properties_and_building_caps(root);
        special_map_prebuilt_properties_preserve_initial_state(root);
        std::cout << "PASS NEW ordinary property purchases and strict affordability ledger\n";
    } catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
}

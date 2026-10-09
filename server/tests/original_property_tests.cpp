#include "original_property.hpp"
#include <algorithm>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class F> void rejects(F action, std::string_view code) {
    try { action(); } catch (const CodecError& error) {
        if (error.what() != code) throw std::runtime_error("expected "+std::string(code)+", got "+error.what()); return;
    }
    throw std::runtime_error("missing rejection: "+std::string(code));
}
std::filesystem::path root() {
    constexpr std::string_view path = __FILE__;
    return std::filesystem::path(std::u8string(path.begin(),path.end())).parent_path().parent_path().parent_path();
}
std::shared_ptr<OriginalMapResources> map() {
    return std::make_shared<OriginalMapResources>(original_map_resources(load_original_emp(root()/"Map"/"BS_1_1.emp"),10));
}
OriginalBuildingPolicy policy() {
    const auto resource = load_original_building_policies(root()/"Data"/"BossWar.kpd");
    return resource.require("BS_1_1.emp");
}
OriginalPropertyActor actor() {
    return {{1000,2000,300},make_original_inventory(),{7,7,7,7,7,7,7,7,7,7},false,false,false,false,false};
}
OriginalResearchQueue research() { return OriginalResearchQueue(load_original_research_resources(root()/"Data"/"BwbValue.kpd").choices); }
OriginalMapProperty& mutable_record(OriginalMapResources& map) {
    const auto found = std::find_if(map.properties.begin(),map.properties.end(),[](const auto& item) { return item.id == 104; });
    check(found != map.properties.end(),"actual property104"); return *found;
}
const OriginalMapProperty& record(const OriginalBossProperties& properties) {
    const auto& records = properties.records();
    return *std::find_if(records.begin(),records.end(),[](const auto& item) { return item.id == 104; });
}
void purchase_is_separate_from_build() {
    OriginalBossProperties properties(0x3456,map(),policy()); auto owner = actor(); auto queue = research();
    check(record(properties).price == 100 && properties.begin({7,0,119,false},owner) == OriginalPropertyStage::purchase,"real map price and purchase entry");
    const auto purchased = properties.handle(OriginalPropertyPurchase{7,0,1,{0x91,0xa2,0xb3}},owner,queue);
    owner = purchased.actor;
    check(purchased.message == Bytes{0x20,0x40,0x56,0x34,1} && purchased.stage == OriginalPropertyStage::complete &&
        owner.funds.cash == 900 && owner.funds.deposit == 2000 && record(properties).owner == 0 && record(properties).level == 0,
        "purchase only changes owner and cash, no same-turn construction");
    rejects([&] { properties.handle(OriginalPropertyPurchase{7,0,1,{}},owner,queue); },"original_property_pending_context_mismatch");
    check(properties.begin({8,0,120,false},owner) == OriginalPropertyStage::build,"adjacent119/120 share property104");
    const auto built = properties.handle(OriginalBuildingChoice{8,11,0xa4},owner,queue);
    check(built.message == Bytes{0x3d,0x40,0x56,0x34,11} && built.stage == OriginalPropertyStage::complete &&
        record(properties).kind == 11 && record(properties).level == 1 && built.actor.funds.cash == 900 &&
        built.actor.inventory == owner.inventory,"default building is free and does not immediately research");
}
void license_stacks_and_failures() {
    for (const std::int8_t kind : {12,13,14,16}) {
        auto resource = map(); mutable_record(*resource).owner = 0;
        OriginalBossProperties properties(0x3456,resource,policy()); auto owner = actor(); auto queue = research();
        properties.begin({9,0,119,false},owner);
        rejects([&] { properties.handle(OriginalBuildingChoice{9,kind,0xcc},owner,queue); },"original_property_build_license_missing");
        check(record(properties).level == 0 && properties.stage() == OriginalPropertyStage::build,"license rejection is atomic");
        owner.inventory[3] = {static_cast<std::int16_t>(kind+498),2,{0x71,0x82}};
        const auto built = properties.handle(OriginalBuildingChoice{9,kind,0xcc},owner,queue);
        check(built.actor.inventory[3] == OriginalCardSlot{static_cast<std::int16_t>(kind+498),1,{0x71,0x82}} &&
            record(properties).kind == kind && record(properties).level == 1 && built.actor.funds.cash == owner.funds.cash,
            "missile/base wall totem pyramid consumes one license, preserves stack tail");
    }
    auto resource = map(); mutable_record(*resource).owner = 0;
    auto custom = policy(); custom.default_kind = 14; custom.level_caps[3] = 0;
    OriginalBossProperties alternate(1,resource,custom); auto owner = actor(); auto queue = research();
    alternate.begin({1,0,119,false},owner);
    check(alternate.handle(OriginalBuildingChoice{1,14,0},owner,queue).actor.inventory == owner.inventory,
        "default building is offered independently of cap and needs no license");
    OriginalBossProperties missing(1,resource,policy()); missing.begin({1,0,119,false},owner);
    rejects([&] { missing.handle(OriginalBuildingChoice{1,15,0},owner,queue); },"original_property_map_cap_unrecovered");
    check(missing.stage() == OriginalPropertyStage::build && record(missing).level == 0,"unknown cap is not guessed disabled or enabled");
}
void upgrade_continuation_and_research() {
    auto resource = map(); auto& saved = mutable_record(*resource); saved.owner = 0; saved.kind = 11; saved.level = 1;
    OriginalBossProperties properties(0x3456,resource,policy()); auto owner = actor(); auto queue = research();
    check(properties.begin({10,0,119,false},owner) == OriginalPropertyStage::upgrade,"below both caps waits56");
    rejects([&] { properties.handle(OriginalClassicUpgrade{10,1,0},owner,queue); },"original_property_classic_upgrade_in_boss_mode");
    rejects([&] { properties.handle(OriginalBossUpgrade{11,1,0},owner,queue); },"original_property_pending_context_mismatch");
    const auto decline = properties.handle(OriginalBossUpgrade{10,0,0xcc},owner,queue);
    check(decline.stage == OriginalPropertyStage::research && decline.message == Bytes{0x3e,0x40,0x56,0x34,0} &&
        record(properties).level == 1,"declined upgrade still runs research branch");
    rejects([&] { properties.handle(OriginalResearchSelection{10,2,0},owner,queue); },"original_research_choice_unavailable");
    check(properties.stage() == OriginalPropertyStage::research && !queue.jobs()[0],"invalid research cannot commit phase or job");
    const auto scheduled = properties.handle(OriginalResearchSelection{10,1,0xa1},owner,queue);
    check(scheduled.message == Bytes{0x3f,0x40,0x56,0x34,1} && scheduled.stage == OriginalPropertyStage::complete &&
        scheduled.research_jobs == std::vector<std::uint8_t>{0,1,2},"owner research schedules three jobs with one403F only");
    properties.begin({11,0,119,false},owner);
    const auto upgraded = properties.handle(OriginalBossUpgrade{11,1,0xa2},owner,queue);
    check(record(properties).level == 2 && upgraded.actor.funds.cash == owner.funds.cash && upgraded.stage == OriginalPropertyStage::research,
        "upgrade costs no money and waits for research");
    check(properties.handle(OriginalResearchSelection{11,-1,0xa3},owner,queue).stage == OriginalPropertyStage::complete,
        "research cancel completes without scheduling more jobs");
}
void cap_skill_and_controlled_states() {
    auto resource = map(); auto& saved = mutable_record(*resource); saved.owner = 0; saved.kind = 13; saved.level = 5;
    auto owner = actor(); auto queue = research();
    OriginalBossProperties wall(1,resource,policy());
    check(wall.begin({1,0,119,false},owner) == OriginalPropertyStage::complete,"maxlevel5 wall does not wait for upgrade decision");
    saved.kind = 11; saved.level = 1; owner.skills[0] = 1;
    OriginalBossProperties unskilled(1,resource,policy());
    check(unskilled.begin({1,0,119,false},owner) == OriginalPropertyStage::research,"skill warning flows into research without33/56");
    for (int status = 0; status < 4; ++status) {
        owner = actor(); owner.sleepwalking = status == 0; owner.confused_god = status == 1;
        owner.hibernating = status == 2; owner.automated = status == 3;
        OriginalBossProperties controlled(1,resource,policy());
        if (status == 3) {
            check(controlled.begin({1,0,119,false},owner) == OriginalPropertyStage::upgrade,"AI may upgrade when not controlled");
            check(controlled.handle(OriginalBossUpgrade{1,0,0},owner,queue).stage == OriginalPropertyStage::complete,"AI skips research UI");
        } else check(controlled.begin({1,0,119,false},owner) == OriginalPropertyStage::complete,"controlled actor skips upgrade and research");
    }
    saved.kind = 16; saved.level = 5; owner = actor(); owner.sleepwalking = true;
    OriginalBossProperties pyramid(1,resource,policy());
    check(pyramid.begin({12,0,119,false},owner) == OriginalPropertyStage::pyramid,"sleepwalker still receives pyramid effect");
    rejects([&] { pyramid.complete_pyramid(11); },"original_property_pyramid_completion_invalid");
    check(pyramid.stage() == OriginalPropertyStage::pyramid,"wrong-context effect cannot release landing");
    pyramid.complete_pyramid(12); check(pyramid.stage() == OriginalPropertyStage::complete,"only explicit applied effect completes pyramid");
}
void purchase_gates_and_visitors() {
    auto resource = map(); auto owner = actor(); auto queue = research(); owner.funds.cash = 100;
    OriginalBossProperties equal(1,resource,policy());
    check(equal.begin({1,0,119,false},owner) == OriginalPropertyStage::complete,"cash equality never opens buy even with deposit");
    owner.purchase_discount = true;
    check(equal.begin({2,0,119,false},owner) == OriginalPropertyStage::purchase,"discount opens affordable normal property");
    check(equal.handle(OriginalPropertyPurchase{2,0,1,{}},owner,queue).actor.funds.cash == 50,"normal property charges halfprice");
    auto special = map(); mutable_record(*special).kind = 10; owner.funds.cash = 101;
    OriginalBossProperties exempt(1,special,policy());
    check(exempt.begin({2,0,119,false},owner) == OriginalPropertyStage::purchase,"special property still admits affordable purchase");
    check(exempt.handle(OriginalPropertyPurchase{2,0,1,{}},owner,queue).actor.funds.cash == 1 && record(exempt).kind == 10,
        "kind10 exempts halfprice without changing purchased kind");
    for (const auto deposit : {10U,70U}) {
        owner.funds.cash = 60; owner.funds.deposit = deposit;
        OriginalBossProperties discounted_gate(1,special,policy());
        check(discounted_gate.begin({3,0,119,false},owner) == OriginalPropertyStage::purchase,
            "kind10 admission uses halfprice even though settlement uses fullprice");
        const auto purchase = discounted_gate.handle(OriginalPropertyPurchase{3,0,1,{}},owner,queue);
        check(purchase.actor.funds.cash == 0 && purchase.actor.funds.deposit == (deposit == 10 ? 0U : 30U) &&
            purchase.stage == OriginalPropertyStage::complete && record(discounted_gate).owner == 0,
            "fullprice uses deposit then clamps zero without inventing a bankruptcy wait");
    }
    owner.funds.cash = 50;
    OriginalBossProperties special_equal(1,special,policy());
    check(special_equal.begin({4,0,119,false},owner) == OriginalPropertyStage::complete,
        "kind10 admission still requires strictly more than discounted price");
    owner = actor(); owner.sleepwalking = true;
    OriginalBossProperties sleeping(1,resource,policy());
    check(sleeping.begin({1,0,119,false},owner) == OriginalPropertyStage::complete,"sleepwalker cannot buy unowned land");
    auto& saved = mutable_record(*resource); saved.owner = 1; saved.kind = 11; saved.level = 5; owner = actor();
    OriginalBossProperties visitor(1,resource,policy());
    check(visitor.begin({1,0,119,false},owner) == OriginalPropertyStage::complete,"enemy research building does not open research");
    check(visitor.begin({2,0,119,true},owner) == OriginalPropertyStage::research,"explicit friendly-owner predicate enables research");
    check(visitor.handle(OriginalResearchSelection{2,1,0},owner,queue).research_jobs.size() == 1,"nonowner friendly visitor has one job");
}
}
int main() {
    try { purchase_is_separate_from_build(); license_stacks_and_failures(); upgrade_continuation_and_research();
        cap_skill_and_controlled_states(); purchase_gates_and_visitors();
        std::cout << "PASS original property real-map purchase, licenses, upgrade branches, research and status gates.\n"; return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}

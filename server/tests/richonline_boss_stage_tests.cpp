#include "richonline_boss_stage.hpp"
#include "original_options.hpp"

#include <algorithm>
#include <iostream>
#include <string>

namespace {
using namespace richnet;
void check(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}
template<class F> void rejects(F action, std::string_view code) {
    try { action(); } catch (const CodecError& error) { check(error.what() == code,error.what()); return; }
    throw std::runtime_error("expected_rejection");
}
std::string decoded(const std::filesystem::path& root) {
    const auto bytes = load_original_kpd(root/"Data/BossWar.kpd");
    std::string text(bytes.begin(),bytes.end());
    std::erase_if(text,[](char c){return c==' ' || c=='\t' || c=='\r';});
    return text;
}
void replace_one(std::string& text, std::string_view old, std::string_view replacement) {
    const auto at = text.find(old);
    check(at != text.npos,"fixture_key_missing");
    text.replace(at,old.size(),replacement);
}
void put(Bytes& bytes, std::size_t at, std::uint32_t value) {
    for (std::size_t i=0;i<4;++i) bytes.at(at+i)=static_cast<std::uint8_t>(value>>(8*i));
}
void four_fresh_stages(const std::filesystem::path& root) {
    constexpr std::array cash{20000U,15000U,20000U,18000U};
    constexpr std::array tickets{150U,300U,300U,300U};
    constexpr std::array boss_cash{100000U,100000U,120000U,150000U};
    constexpr std::array dice{1U,2U,3U,3U};
    constexpr std::array pawn{100U,500U,1000U,1500U};
    constexpr std::array<std::uint8_t,10> caps{5,5,5,5,0,5,0,0,0,0};
    for (std::size_t i=0;i<4;++i) {
        const auto name="BS_1_"+std::to_string(i+1)+".emp";
        const auto stage=load_richonline_boss_stage(root,name);
        check(stage.map_id==11+i && stage.map_name==name && stage.mode==3 && stage.width==16 && stage.height==18,
              "stage_identity_wrong");
        check(stage.human.cash==cash[i] && stage.human.deposit==0 && stage.human.tickets==tickets[i] &&
              stage.monetary_scale==1,"EMP_balances_wrong");
        check(stage.boss.base_cash==boss_cash[i] && stage.boss.max_dice==dice[i] && stage.pawn_gold==pawn[i],
              "BossWar_parameters_wrong");
        check(stage.wait_seconds==10 && stage.game_months==3 && stage.player_selection==4 &&
              stage.player_count_choices==std::vector<std::uint32_t>{1,2,3,4},"room_parameters_wrong");
        check(stage.boss.count==1 && stage.boss.role==0 && stage.boss.mood==9 && stage.boss.equipment[6]==31,
              "boss_identity_wrong");
        check(stage.default_building_kind==11 && stage.scenario_caps==caps && stage.boss.building_skills==caps,
              "construction_parameters_wrong");
    }
}
void zhao_uses_special_category_resources(const std::filesystem::path& root) {
    const auto stage=load_richonline_boss_stage(root,"V_BS_1_1.emp",2);
    check(stage.category==2 && stage.map_id==11 && stage.map_name=="V_BS_1_1.emp","special_stage_identity_wrong");
    check(stage.human.cash==12000 && stage.human.deposit==0 && stage.human.tickets==350 &&
        stage.boss.base_cash==150000 && stage.boss.role==-1 && stage.boss.mood==12 &&
        stage.boss.equipment[6]==67 && stage.pawn_gold==0,"special_stage_used_ordinary_resources");
    const std::array<std::uint8_t,10> caps{6,6,6,6,0,6,0,0,0,0};
    check(stage.scenario_caps==caps && stage.boss.building_skills==caps && stage.boss.max_dice==3,
        "special_stage_skills_or_dice_wrong");
    rejects([&]{load_richonline_boss_stage(root,"V_BS_1_1.emp",0);},"richonline_stage_map_unsupported");
    rejects([&]{load_richonline_boss_stage(root,"BS_1_1.emp",2);},"richonline_stage_map_unsupported");
    rejects([&]{load_richonline_boss_stage(root,"V_BS_1_2.emp",2);},"richonline_stage_map_resource_missing");
}
void malformed_resources(const std::filesystem::path& root) {
    const auto source=decoded(root);
    const auto map=load_original_emp(root/"Map/BS_1_1.emp");
    const auto parse=[&](std::string_view text) { return parse_richonline_boss_stage(text,"BS_1_1.emp",map); };
    auto text=source; replace_one(text,"bossMaxDice=1","bossMaxDice=-1");
    rejects([&]{parse(text);},"richonline_stage_range:bossMaxDice");
    text=source; replace_one(text,"maxLev_Yan=5","maxLev_Yan=8");
    rejects([&]{parse(text);},"richonline_stage_range:maxLev_Yan");
    text=source; replace_one(text,"defaultBuild=Yan","defaultBuild=Unknown");
    rejects([&]{parse(text);},"richonline_stage_default_building_invalid");
    text=source; replace_one(text,"bossInitCash=100000","bossInitCash=100000x");
    rejects([&]{parse(text);},"richonline_stage_number:bossInitCash");
    text=source; replace_one(text,"bossInitCash=100000","bossInitCash=2147483648");
    rejects([&]{parse(text);},"richonline_stage_number:bossInitCash");
    text=source; replace_one(text,"bossInitCash=100000","missingCash=100000");
    rejects([&]{parse(text);},"richonline_stage_missing:bossInitCash");
    text=source; replace_one(text,"bossInitCash=100000","bossInitCash=100000\nbossInitCash=1");
    rejects([&]{parse(text);},"richonline_stage_duplicate_key:bossInitCash");
    text=source; replace_one(text,"plyNum=1,2,3,4","plyNum=1,1");
    rejects([&]{parse(text);},"richonline_stage_player_choices_invalid");
    rejects([&]{parse(source+source);},"richonline_stage_record_ambiguous");
    rejects([&]{parse_richonline_boss_stage(source,"../BS_1_1.emp",map);},"richonline_stage_map_unsupported");
    auto bad=map; put(bad.header,23300,12);
    rejects([&]{parse_richonline_boss_stage(source,"BS_1_1.emp",bad);},"richonline_stage_map_metadata_mismatch");
    bad=map; bad.payload.resize(bad.tail_offset+110);
    rejects([&]{parse_richonline_boss_stage(source,"BS_1_1.emp",bad);},"richonline_stage_EMP_truncated");
    bad=map; put(bad.payload,bad.tail_offset+104,0xffffffffU);
    rejects([&]{parse_richonline_boss_stage(source,"BS_1_1.emp",bad);},"richonline_stage_range:human_cash");
}
void values_come_from_resources(const std::filesystem::path& root) {
    auto text=decoded(root);
    auto map=load_original_emp(root/"Map/BS_1_1.emp");
    replace_one(text,"bossInitCash=100000","bossInitCash=123456");
    replace_one(text,"bossSuit=31","unusedSuit=31");
    replace_one(text,"bossSkill_Yan=5","unusedSkill_Yan=5");
    replace_one(text,"maxLev_Yan=5","unusedLev_Yan=5");
    replace_one(text,"bossRole=0","bossRole=-1");
    put(map.payload,map.tail_offset+104,23456);
    const auto stage=parse_richonline_boss_stage(text,"BS_1_1.emp",map);
    check(stage.human.cash==23456 && stage.boss.base_cash==123456,"resource_values_were_hardcoded");
    check(stage.boss.equipment[6]==0 && stage.boss.building_skills[0]==0 && stage.scenario_caps[0]==0,
          "missing_optional_fields_not_zero_initialized");
    check(stage.boss.role==-1,"signed_resource_role_lost");
    constexpr std::array<std::uint8_t,16> signature{0x77,0x2a,0x81,0xa7,0x87,0x67,0x85,0x52,
        0x15,0x57,0x8e,0xcf,0xf3,0x9c,0x3a,0xbe};
    check(stage.signature==signature,"requires_actual_NEW_map_signature");
}
void rewards_use_counted_resource_lists(const std::filesystem::path& root) {
    const auto source=decoded(root);
    const auto map=load_original_emp(root/"Map/BS_1_1.emp");
    const auto parse=[&](std::string_view text) { return parse_richonline_boss_stage(text,"BS_1_1.emp",map); };
    const auto stage=parse(source);
    check(stage.first_reward.experience==10 && stage.first_reward.gold==20 && stage.first_reward.item_count==1 &&
          stage.first_reward.item_ids==std::vector<std::int32_t>{1125},"first_reward_not_resource_value");
    check(stage.repeat_reward.experience==5 && stage.repeat_reward.gold==8 && stage.repeat_reward.item_count==8 &&
          stage.repeat_reward.item_ids==std::vector<std::int32_t>{4,200,201,202,203,204,205,206},"repeat_reward_not_resource_value");
    const auto zhao=load_richonline_boss_stage(root,"V_BS_1_1.emp",2);
    check(zhao.first_reward.item_count==0 && zhao.first_reward.item_ids.empty() &&
          zhao.repeat_reward.item_count==0 && zhao.repeat_reward.item_ids.empty(),"disabled_zhao_rewards_loaded");
    auto text=source; replace_one(text,"firstExp=10","firstExp=32768");
    replace_one(text,"firstGold=20","firstGold=2147483647");
    check(parse(text).first_reward.experience==32768 && parse(text).first_reward.gold==2147483647,
          "resource_reward_narrowed_to_wire_width");
    text=source; replace_one(text,"firstExp=10","firstExp=-1");
    rejects([&] { parse(text); },"richonline_stage_range:firstExp");
    text=source; replace_one(text,"firstGold=20","firstGold=2147483648");
    rejects([&] { parse(text); },"richonline_stage_number:firstGold");
    text=source; replace_one(text,"firstPropNum=1","firstPropNum=9");
    rejects([&] { parse(text); },"richonline_stage_range:firstPropNum");
    text=source; replace_one(text,"firstPropNum=1","firstPropNum=2");
    rejects([&] { parse(text); },"richonline_stage_reward_list_short:first");
    text=source; replace_one(text,"firstProp=1125","firstProp=bad");
    rejects([&] { parse(text); },"richonline_stage_reward_item_invalid:first");
    replace_one(text,"firstPropNum=1","firstPropNum=0");
    check(parse(text).first_reward.item_ids.empty(),"zero_count_parsed_ignored_list");
    text=source; replace_one(text,"firstProp=1125","firstProp=1125,not-consumed");
    check(parse(text).first_reward.item_ids==std::vector<std::int32_t>{1125},"reward_ignored_tail_became_active");
    text=source; replace_one(text,"firstPropNum=1","firstPropNum=2");
    replace_one(text,"firstProp=1125","firstProp=1125,1125");
    check(parse(text).first_reward.item_ids==std::vector<std::int32_t>{1125,1125},"reward_list_duplicates_lost");
    text=source; replace_one(text,"firstExp=10","missingExp=10");
    rejects([&] { parse(text); },"richonline_stage_missing:firstExp");
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"expected_NEW_client_root");
        const std::filesystem::path root(argv[1]);
        four_fresh_stages(root); zhao_uses_special_category_resources(root); malformed_resources(root); values_come_from_resources(root);
        rewards_use_counted_resource_lists(root);
        std::cout<<"richonline boss stage tests passed\n"; return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}

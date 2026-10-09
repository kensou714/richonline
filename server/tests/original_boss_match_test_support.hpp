#pragma once
#include "original_boss_match.hpp"
#include "original_game_startup_test_support.hpp"
#include "original_options.hpp"
#include <set>
#include <iostream>

namespace original_boss_match_test {
using namespace original_startup_test;
struct Fixture {
    std::atomic_int seconds{0};
    std::mutex diagnostic_mutex;
    std::string request_failure;
    std::shared_ptr<OriginalBossMatch> match;
    OriginalStartup expected_startup;
    explicit Fixture(OriginalBossSpawn human = {179,1}, OriginalBossSpawn boss = {123,1}, std::uint8_t attack_attempts = 0) {
        constexpr std::string_view source = __FILE__;
        const auto root = std::filesystem::path(std::u8string(source.begin(),source.end())).parent_path().parent_path().parent_path();
        const auto prop = load_original_prop_cards(root/"Data"/"Prop.kpd");
        std::set<std::int16_t> known;
        for (const auto& card : prop.cards) known.insert(card.id);
        const auto config = OriginalBossConfig::load(root/"local-server"/"boss-stages.json",known);
        auto map = original_map_resources(load_original_emp(root/"Map"/"BS_1_1.emp"),load_original_price_base(root/"Data"/"Option.kpd"));
        const auto boss_landing = std::find_if(map.roads.begin(),map.roads.end(),[](const auto& road) { return road.tile == 122; });
        const auto human_landing = std::find_if(map.roads.begin(),map.roads.end(),[](const auto& road) { return road.tile == 178; });
        require(boss_landing != map.roads.end() && boss_landing->type == 42 && human_landing != map.roads.end() &&
            human_landing->type == 10,"boss_match_actual_landing_types_wrong");
        Bytes wire(208);
        wire[0] = 'T';
        const std::string name = "BS_1_1.emp";
        std::copy(name.begin(),name.end(),wire.begin()+128);
        std::copy(map.emp.signature.begin(),map.emp.signature.end(),wire.begin()+160);
        const auto put = [&](std::size_t offset,std::uint32_t value) {
            for (std::size_t i = 0; i < 4; ++i) wire.at(offset+i) = static_cast<std::uint8_t>(value>>(8*i));
        };
        for (const auto offset : {40U,44U,180U}) put(offset,1);
        put(32,0x40); put(120,80); put(176,3);
        const OriginalBossBoardRequest request{{wire,name,1},25,human,boss,0x3456,0x1234ffff,{2026,10,9,6},3.25,
            {7,7,7,7,7,7,7,7,7,7},0xa1,0xb2,0xc3,{0x91},{0x92},{-123,-7,{0x12,0x34,0x56,0x78}}};
        auto board = prepare_original_boss_board(map,config,request);
        board.settings.attack.attempts = attack_attempts;
        expected_startup = board.startup;
        const auto policies = load_original_building_policies(root/"Data"/"BossWar.kpd");
        const auto found = std::find_if(policies.maps.begin(),policies.maps.end(),[](const auto& policy) { return policy.map_name == "BS_1_1.emp"; });
        require(found != policies.maps.end() && found->default_kind.has_value(),"boss_match_fixture_policy_missing");
        OriginalBossMatchResources resources{std::make_shared<OriginalCardCombinations>(load_original_card_combinations(root/"Data"/"CombCard.kpd")),
            original_shop_catalog(prop,map),{*found->default_kind,found->level_caps},load_original_research_resources(root/"Data"/"BwbValue.kpd").choices};
        OriginalBossMatchPolicy policy{{1,1},
            {{{0xa5,0xb6,0xc7,0xd8,0xe9,0xfa,0x8b,0x9c,0xad,0xbe,0xcf,0xd0,0xe1},{0xfa,0xce},{0xbe,0xef}},
                {0xd1},{0xd2},{0xd3},{0x71,0x82,0x93},0xa4},
            [](std::uint32_t) { return 0U; },[this] { return OriginalShopClock::time_point{}+std::chrono::seconds(seconds.load()); }};
        match = std::make_shared<OriginalBossMatch>(std::move(board),std::move(resources),std::move(policy));
    }
};
inline GameCallbacks callbacks(Fixture& fixture) {
    const auto match = fixture.match;
    auto result = direct_callbacks(original_boss_match_plan(match));
    result.message = [receive = std::move(result.message),match,&fixture](const GameAdmission& admission,const Envelope299& envelope,View plain) {
        try { return receive(admission,envelope,plain); }
        catch (const std::exception& error) {
            {
                const std::lock_guard lock(fixture.diagnostic_mutex);
                fixture.request_failure = error.what();
            }
            std::cerr << "boss_match_tcp_request_failed opcode=" << read_le(plain.first(2))
                << " context=" << match->context() << " actor=" << static_cast<unsigned>(match->current_slot())
                << " reason=" << error.what() << '\n';
            throw;
        }
    };
    return result;
}
inline void no_packet(const Client& client) {
    fd_set readable; FD_ZERO(&readable); FD_SET(client.socket,&readable);
    timeval timeout{0,150000};
    require(select(0,&readable,nullptr,nullptr,&timeout) == 0,"boss_match_unexpected_automatic_turn");
}
inline Bytes roll(std::uint8_t start, std::uint8_t direction) {
    return {0x11,0x40,0x56,0x34,start,0,1,1,1,0,0,static_cast<std::uint8_t>(0xa4U|direction),
        0xb6,0xc7,0xd8,0xe9,0xfa,0x8b,0x9c,0xad,0xbe,0xcf,0xd0,0xe1,0,0,0,0};
}
}

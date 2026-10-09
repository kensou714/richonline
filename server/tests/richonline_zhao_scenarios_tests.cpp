// Independent special-map admission and encrypted long-game regression.
#define main heibeibei_driver_unused_main
#include "richonline_heibeibei_scenarios_tests.cpp"
#undef main

namespace {
RichonlineRoomSnapshot zhao_room(const std::filesystem::path& root,std::uint32_t actor) {
    const auto stage=load_richonline_boss_stage(root,"V_BS_1_1.emp",2);
    RichonlineRoomSnapshot result{3,actor,{},{{77,actor,0,true}},2};
    auto& ext=result.description.extension;ext=Bytes(88,0);
    std::copy(stage.map_name.begin(),stage.map_name.end(),ext.begin());
    std::copy(stage.signature.begin(),stage.signature.end(),ext.begin()+32);
    put32(ext,48,stage.mode);put32(ext,52,1);put32(ext,56,stage.wait_seconds);
    put32(ext,60,stage.game_months);put32(ext,64,stage.pawn_gold);put32(ext,68,2);
    result.description.record[32]=0x40;result.description.record[36]=3;
    result.description.record[40]=1;result.description.record[120]=88;result.description.record[124]=1;
    return result;
}
}
int main(int argc,char** argv) {
    try {
        require(argc==4,"usage: resources bootstrap output-directory");
        const std::filesystem::path resources=std::filesystem::absolute(argv[1]);
        const std::filesystem::path bootstrap=std::filesystem::absolute(argv[2]);
        const std::filesystem::path output=std::filesystem::absolute(argv[3]);
        std::filesystem::create_directories(output);
        const auto& package=find_richonline_map_package("V_BS_1_1.emp",2);
        const auto rules=load_richonline_map_rule_resources(resources,package,2);
        require(package.special_category,"special_category_lost");
        require(rules.stage.category==2 && rules.stage.map_id==11 && rules.stage.boss.role==-1 &&
            rules.stage.boss.mood==12 && rules.stage.boss.equipment[6]==67,"special_identity_lost");
        require(rules.stage.boss.base_cash==150000 && rules.stage.boss.max_dice==3 &&
            rules.stage.human.cash==12000 && rules.stage.human.tickets==350 && rules.stage.pawn_gold==0,"special_economics_lost");
        require(rules.stage.scenario_caps==std::array<std::uint8_t,10>{6,6,6,6,0,6,0,0,0,0},"special_skills_lost");
        require(rules.portals[1]==std::optional<std::array<std::int16_t,2>>{{105,229}},"special_portals_lost");
        for(const auto& cell:rules.topology.cells()) if(cell.walkable)
            std::cout<<Json{{"event","cell"},{"position",cell.position},{"static",cell.static_type},{"property",cell.property_ref}}.dump()<<'\n';
        const auto chance=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(resources));
        const auto news=RichonlineChanceEventTable::load(resources);
        const auto status=RichonlineStatusRules::load(resources);
        require(news.size(package.map_name)==34,"special_events_not_independent");
        const auto policy=package.configure({"other.emp",999,999,{0xa5,0x5a}});
        require(policy.map_name==package.map_name && policy.event_id==2 && policy.card_id==1038,"special_reward_event_wrong");
        RichonlineBossCards cards(chance,7,policy);
        cards.configure_tile_rewards(package.closed_chance->playable_reward_cards,[](std::size_t){return std::size_t{0};});
        require(cards.tile_reward_cards()==package.closed_chance->playable_reward_cards,"special_card_pool_not_present");
        const auto chance_policy=make_richonline_closed_chance_policy(news,package.map_name,package.closed_chance->playable_reward_cards,true,{0xa5,0x5a});
        for(const auto& cell:rules.topology.cells()) if(cell.walkable)
            require(richonline_map_static_rule(cell).effect!=RichonlineMapStaticEffect::unsupported &&
                richonline_map_static_rule(cell).effect!=RichonlineMapStaticEffect::pending_server_reward,"special_static_unclosed");
        for(const std::int8_t type:std::array<std::int8_t,3>{68,69,70}) for(std::uint8_t actor=0;actor<2;++actor)
            for(const bool last:{false,true}) {
                const RichonlineLandingContext context{actor,100,type,-1,3,actor==1,2,false,{}};
                const auto attempt=prepare_richonline_chance_landing(news,*chance,status,chance_policy,context,7,
                    {{30000,0,300,std::nullopt},0},{},[last](std::size_t count){return last?count-1:0;});
                require(attempt.disposition==RichonlineChanceLandingDisposition::prepared,"special_chance_color_unclosed");
            }
        const auto fixture=output/("zhao-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())+".sqlite3");
        Storage storage(fixture,ClientProfile::richonline);
        const auto actor=storage.dispatch("accounts.create",{{"username","multi-fixture"},{"password","local-only"}}).at("account").at("role_id").get<std::uint32_t>();
        const auto decoded=[&](const char* name) {const auto bytes=load_original_kpd(resources/"Data"/name,8U*1024U*1024U);return std::string(bytes.begin(),bytes.end());};
        const auto combat=RichonlineCombatResources::parse(decoded("Prop.kpd"),decoded("Npc.kpd"),decoded("GValue.kpd"));
        Totals totals;std::optional<std::uint16_t> pending_property;
        std::vector<Json> diagnostics;
        unsigned opponent_properties=0,graceful_exits=0;
        std::ofstream trace(output/"V_BS_1_1.emp.trace.jsonl");require(trace.good(),"trace_open_failed");
        auto runtime=load_richonline_boss_runtime(storage,bootstrap,[&](const std::string& event,const Json& values) {
            if(event=="richonline_property_landed") {
                if(values.at("pending_opcode").get<unsigned>()!=0)
                    pending_property=values.at("pending_opcode").get<std::uint16_t>();
                const auto owner=values.at("owner").get<unsigned>();
                if(owner<2 && owner!=values.at("actor_slot").get<unsigned>())++opponent_properties;
                trace<<Json{{"event",event},{"values",values}}.dump()<<'\n';
            }
            const bool expected_cleanup=event=="richonline_terminal_cleanup" && values.value("reason","")=="game_connection_closed";
            if(values.value("level","")=="warning" && !expected_cleanup)
                diagnostics.push_back({{"event",event},{"values",values}});
        });
        require(runtime.has_value(),"runtime_missing");
        require(rules.conservative_spawns.has_value(),"special_spawns_missing");
        trace<<Json{{"event","resource_verified"},{"map",package.map_name},{"channel",2},{"category",2},
            {"game_months",rules.stage.game_months},{"wait_seconds",rules.stage.wait_seconds},
            {"human_cash",rules.stage.human.cash},{"boss_cash",rules.stage.boss.base_cash},
            {"events",news.size(package.map_name)},{"closed_events",chance_policy.entries.size()}}.dump()<<'\n';
        for(unsigned session=0;session<3;++session) {
            const auto losses_before=storage.roles_for_username("multi-fixture").at(0).at("losses").get<std::uint32_t>();
            auto plans=runtime->provider(19001,zhao_room(resources,actor));require(plans.size()==1,"special_map_start_missing_plan");
            auto transport=std::make_unique<TcpPlan>(plans.front());
            Driver driver{transport->facade,rules.topology,totals,pending_property,combat,trace,storage,actor,news,std::string(package.map_name),status};
            driver.positions={rules.conservative_spawns->at(0).position,rules.conservative_spawns->at(1).position};
            try {
                driver.run(320,static_cast<std::uint8_t>(rules.stage.boss.max_dice));
                if(!driver.terminal) {
                    driver.send(Bytes{0x0a,0x00});
                    require(driver.has(0x4006),"special_map_graceful_leave_ack_missing");
                    ++graceful_exits;
                }
            }
            catch(const std::exception& error) {
                std::cerr<<Json{{"event","driver_failed"},{"map",package.map_name},{"session",session},{"calendar",driver.calendar},
                    {"actor",driver.actor},{"positions",driver.positions},{"last_request",driver.last_request},
                    {"last_response",driver.last},{"reason",error.what()},{"diagnostics",diagnostics},
                    {"transport_logs",transport->logs()},{"totals",totals.json()}}.dump()<<'\n';
                transport.reset();plans.front().disconnected();throw;
            }
            transport.reset();plans.front().disconnected();
            if(!driver.terminal)
                require(storage.roles_for_username("multi-fixture").at(0).at("losses").get<std::uint32_t>()==losses_before+1,
                    "special_map_graceful_leave_loss_not_exactly_once");
            require(storage.pending_game_settlements("multi-fixture",actor).empty(),"special_terminal_database_outbox_pending");
            std::cout<<Json{{"event","session_complete"},{"map",package.map_name},{"session",session},{"terminal",driver.terminal},
                {"graceful_leave",!driver.terminal},{"totals",totals.json()}}.dump()<<'\n';
        }
        require(totals.turns>=40 && totals.attacks>0 && totals.controlled_cards==3 && totals.selected_dice>=3 && totals.returns+graceful_exits==3,
            "insufficient_special_map_runtime_coverage");
        require(opponent_properties>0,"special_opponent_property_not_exercised");
        require(diagnostics.empty(),"special_map_runtime_warnings");
        std::cout<<Json{{"event","map_pass"},{"map",package.map_name},{"transport","encrypted GameService TCP"},{"totals",totals.json()},
            {"opponent_property_landings",opponent_properties},{"graceful_exits",graceful_exits},
            {"database",utf8(fixture)},{"client_ui_verified",false},{"live_data_touched",false}}.dump()<<'\n';
        return 0;
    }catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
}

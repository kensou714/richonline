// Adapted from the retained wave25 encrypted TCP integration driver.
// Isolated candidate integration driver. It sends only decoded, supported client
// decisions; an unresolved phase is a failure, never a synthetic turn advance.
#include "richonline_boss_runtime.hpp"
#include "richonline_boss_session.hpp"
#include "richonline_levels.hpp"
#include "richonline_game_end.hpp"
#include "richonline_chance_landing.hpp"
#include "original_map.hpp"
#include "original_options.hpp"
#include "service.hpp"
#include <sqlite3.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <thread>

namespace {
using namespace richnet;
using Json=nlohmann::json;
void require(bool value,const char* reason) {if(!value)throw std::runtime_error(reason);}
std::string utf8(const std::filesystem::path& path) {const auto value=path.generic_u8string();return {value.begin(),value.end()};}
void put32(Bytes& record,std::size_t offset,std::uint32_t value) {
    for(std::size_t i=0;i<4;++i)record.at(offset+i)=static_cast<std::uint8_t>(value>>(8*i));
}
RichonlineRoomSnapshot make_room(const std::filesystem::path& root,std::uint32_t actor,std::string_view name) {
    RichonlineRoomSnapshot result{3,actor,{},{{77,actor,0,true}}};
    auto& ext=result.description.extension;ext=Bytes(88,0);
    std::copy(name.begin(),name.end(),ext.begin());
    const auto map=load_original_emp(root/"Map"/name);
    std::copy(map.signature.begin(),map.signature.end(),ext.begin()+32);
    const auto stage=load_richonline_boss_stage(root,name,0);
    put32(ext,48,stage.mode);put32(ext,52,1);put32(ext,56,stage.wait_seconds);
    put32(ext,60,stage.game_months);put32(ext,64,stage.pawn_gold);
    result.description.record[32]=0x40;result.description.record[36]=3;
    result.description.record[40]=1;result.description.record[120]=88;result.description.record[124]=1;
    return result;
}
Bytes request(std::uint16_t opcode,std::uint16_t calendar,std::uint32_t argument=0,std::size_t width=2) {
    Bytes result;append_le(result,opcode,2);append_le(result,calendar,2);append_le(result,argument,width);return result;
}
std::uint16_t code(View bytes) {require(bytes.size()>=2,"short_plain");return static_cast<std::uint16_t>(read_le(bytes.first(2)));}
Bytes unpack(const Frame& frame) {return decode_inner(decode_envelope(frame,ClientVersion::richonline).encoded);}
struct Totals {
    unsigned turns=0,moves=0,attacks=0,npc_pickups=0,wealth=0,fortune=0,chest=0,shops=0,banks=0,properties=0,junctions=0,returns=0;
    std::map<std::uint16_t,unsigned> opcodes;
    unsigned research=0,selected_dice=0,controlled_cards=0,chance=0;
    Json json() const {return {{"turns",turns},{"moves",moves},{"boss_attacks",attacks},{"npc_pickups",npc_pickups},
        {"wealth",wealth},{"fortune",fortune},{"chest",chest},{"shop_exits",shops},{"bank_exits",banks},
        {"property_decisions",properties},{"junction_decisions",junctions},{"lobby_returns",returns},{"opcode_counts",opcodes},
        {"research_decisions",research},{"dice_selection_payments",selected_dice},{"controlled_card_uses",controlled_cards},{"chance_events",chance}};}
};
// The original runtime plan remains behind GameSession/GameService. The facade
// performs real outer-frame encryption, TCP I/O and frame decoding. Lifecycle
// inspection/58 confirmation is serialized through the same lock; lobby TCP and
// login are explicitly outside this independent game-transport harness.
class TcpPlan final {
    RichonlineGamePlan& actual_;
    std::mutex mutex_;
    std::unique_ptr<GameService> service_;
    std::thread worker_;
    SOCKET socket_=INVALID_SOCKET;
    GameAdmission admission_{0,3,0,{1,2,3,4,5,6,7,8},0x12345678,{}};
    bool winsock_=false;
    std::vector<std::string> logs_;
    void write(const Frame& frame) {
        const auto bytes=encode_frame(frame,{Channel::game_c2s,{},ClientVersion::richonline});
        for(std::size_t offset=0;offset<bytes.size();) {
            const auto result=::send(socket_,reinterpret_cast<const char*>(bytes.data()+offset),static_cast<int>(bytes.size()-offset),0);
            require(result>0,"tcp_send_failed");offset+=static_cast<std::size_t>(result);
        }
    }
    Bytes read(std::size_t count) {
        Bytes bytes(count);
        for(std::size_t offset=0;offset<count;) {
            const auto result=recv(socket_,reinterpret_cast<char*>(bytes.data()+offset),static_cast<int>(count-offset),0);
            require(result>0,"tcp_receive_closed_or_timed_out");offset+=static_cast<std::size_t>(result);
        }
        return bytes;
    }
    std::vector<Frame> receive_batch(bool stop_after_leave_ack=false) {
        std::vector<Frame> result;
        for(;;) {
            fd_set ready;FD_ZERO(&ready);FD_SET(socket_,&ready);
            timeval timeout{result.empty()?3L:0L,result.empty()?0L:30000L};
            const auto available=select(0,&ready,nullptr,nullptr,&timeout);
            require(available>=0,"tcp_select_failed");
            if(available==0) {require(!result.empty(),"tcp_response_missing");return result;}
            auto bytes=read(8);const auto total=read_le(View(bytes).subspan(4,4));
            require(total>=8 && total<=max_frame_total,"tcp_bad_frame_length");
            auto payload=read(total-8);bytes.insert(bytes.end(),payload.begin(),payload.end());
            result.push_back(decode_frame(bytes,{Channel::game_s2c,{},ClientVersion::richonline}));
            if(stop_after_leave_ack && result.back().wire_type==299 && code(unpack(result.back()))==0x4006)
                return result;
        }
    }
public:
    RichonlineGamePlan facade;
    explicit TcpPlan(RichonlineGamePlan& actual):actual_(actual) {
        WSADATA data{};require(WSAStartup(MAKEWORD(2,2),&data)==0,"winsock_start_failed");winsock_=true;
        admission_.id2=actual.actor;
        try {
            service_=std::make_unique<GameService>(ServiceOptions{"127.0.0.1",0,ClientVersion::richonline},[this] {
                return GameCallbacks{
                    [this](const GameAdmission& value){return value==admission_;},
                    [this](const GameAdmission&){const std::lock_guard lock(mutex_);return actual_.admitted();},
                    [this](const GameAdmission&,const Envelope299& envelope,View plain){const std::lock_guard lock(mutex_);return actual_.message(envelope,plain);},
                    [this](const GameAdmission&){const std::lock_guard lock(mutex_);actual_.disconnected();},
                    [this](const GameAdmission&){const std::lock_guard lock(mutex_);return actual_.poll?actual_.poll():std::vector<Frame>{};},
                    [this](const GameAdmission&,const Frame& frame){const std::lock_guard lock(mutex_);if(actual_.sent)actual_.sent(frame);},{}};
            },[this](const std::string& line){const std::lock_guard lock(mutex_);logs_.push_back(line);});
            worker_=std::thread([this]{try{service_->run();}catch(const std::exception& e){const std::lock_guard lock(mutex_);logs_.push_back(e.what());}});
            const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds{3};
            while(service_->bound_port()==0 && std::chrono::steady_clock::now()<deadline)std::this_thread::sleep_for(std::chrono::milliseconds{5});
            require(service_->bound_port()!=0,"tcp_listener_missing");
            socket_=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);require(socket_!=INVALID_SOCKET,"tcp_socket_failed");
            const DWORD timeout=3000;
            for(const auto option:{SO_RCVTIMEO,SO_SNDTIMEO})require(setsockopt(socket_,SOL_SOCKET,option,reinterpret_cast<const char*>(&timeout),sizeof(timeout))==0,"tcp_timeout_setup_failed");
            const BOOL no_delay=TRUE;require(setsockopt(socket_,IPPROTO_TCP,TCP_NODELAY,reinterpret_cast<const char*>(&no_delay),sizeof(no_delay))==0,"tcp_nodelay_failed");
            sockaddr_in address{};address.sin_family=AF_INET;address.sin_port=htons(service_->bound_port());
            require(inet_pton(AF_INET,"127.0.0.1",&address.sin_addr)==1,"tcp_address_invalid");
            require(connect(socket_,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,"tcp_connect_failed");
            facade.connection=actual.connection;facade.actor=actual.actor;facade.redirect=actual.redirect;
            facade.admitted=[this]{write(encode_game_admission(admission_,ClientVersion::richonline));return receive_batch();};
            facade.message=[this](const Envelope299&,View plain){
                write(richonline_board_frame(plain,{7,-2},Bytes(plain.size()+2,0x91)));
                if(code(plain)==0x14) {
                    fd_set ready;FD_ZERO(&ready);FD_SET(socket_,&ready);timeval delay{0,80000};
                    require(select(0,&ready,nullptr,nullptr,&delay)==0,"dice_selection_unexpected_response");
                    const std::lock_guard lock(mutex_);return std::vector<Frame>{};
                }
                auto result=receive_batch(code(plain)==0x0a);
                // Synchronize the diagnostic projection with the room callback.
                const std::lock_guard lock(mutex_);return result;
            };
            facade.disconnected=[]{};
            facade.game_finished=[this]{const std::lock_guard lock(mutex_);return actual_.game_finished && actual_.game_finished();};
            facade.lobby_sent=[this](const Frame& frame){const std::lock_guard lock(mutex_);actual_.lobby_sent(frame);};
        }catch(...){close();throw;}
    }
    void close() {
        if(socket_!=INVALID_SOCKET){closesocket(socket_);socket_=INVALID_SOCKET;}
        if(service_)service_->stop();if(worker_.joinable())worker_.join();
        if(winsock_){WSACleanup();winsock_=false;}
    }
    ~TcpPlan(){close();}
    std::vector<std::string> logs(){const std::lock_guard lock(mutex_);return logs_;}
};
struct Driver {
    RichonlineGamePlan& plan;
    const RichonlineRoadTopology& topology;
    Totals& total;
    std::ofstream& trace;
    std::optional<std::uint16_t>& pending_property;
    std::uint16_t calendar=0;
    std::uint8_t actor=1;
    unsigned turns=0;
    bool terminal=false;
    std::optional<Bytes> movement;
    std::map<std::int16_t,std::uint8_t> ground;
    std::vector<RichonlineMine> mines;
    const RichonlineCombatResources& combat;
    std::vector<Bytes> last;
    std::array<std::int16_t,2> positions{};
    Bytes last_request;
    Storage& storage;
    std::uint32_t role;
    unsigned human_rolls=0;
    const RichonlineChanceEventTable& news;
    std::string map_name;
    RichonlineStatusRules status_rules;
    std::array<std::uint8_t,2> forced_step_turns{};
    Driver(RichonlineGamePlan& value,const RichonlineRoadTopology& map,Totals& counts,std::optional<std::uint16_t>& pending,
        const RichonlineCombatResources& rules,std::ofstream& output,Storage& store,std::uint32_t owner,
        const RichonlineChanceEventTable& events,std::string name,RichonlineStatusRules timers)
        :plan(value),topology(map),total(counts),trace(output),pending_property(pending),combat(rules),storage(store),role(owner),
        news(events),map_name(std::move(name)),status_rules(timers) {}
    void explode(std::int16_t root) {
        if(std::none_of(mines.begin(),mines.end(),[root](const auto& m){return m.position==root;}))return;
        const auto graph=plan_richonline_mine_chain(root,mines,combat.mine_range,[&](std::int16_t pos,std::uint8_t dir)->std::optional<std::int16_t> {
            const auto width=static_cast<std::int32_t>(topology.width());const auto height=static_cast<std::int32_t>(topology.height());
            auto x=pos%width,y=pos/width;
            if(dir==0)++y;else if(dir==1)--x;else if(dir==2)--y;else ++x;
            if(x<0 || y<0 || x>=width || y>=height)return {};
            return static_cast<std::int16_t>(y*width+x);
        });
        for(const auto pos:graph.affected_positions)ground.erase(pos);
        std::erase_if(mines,[&](const auto& m){return std::find(graph.detonated_mines.begin(),graph.detonated_mines.end(),m.position)!=graph.detonated_mines.end();});
    }
    void ingest(const std::vector<Frame>& frames) {
        last.clear();
        for(const auto& frame:frames) {
            if(frame.wire_type==299) {
                auto plain=unpack(frame);const auto op=code(plain);++total.opcodes[op];
                trace<<Json{{"direction","s2c"},{"wire_type",frame.wire_type},{"opcode",op},{"plain",plain}}.dump()<<'\n';
                if(op==0x4004)calendar=static_cast<std::uint16_t>(read_le(View(plain).subspan(4,4)));
                if(op==0x4010) {
                    if(plain.at(6)==0 && forced_step_turns[actor]) --forced_step_turns[actor];
                    actor=plain.at(4);if(plain.at(6)==0){++calendar;++turns;++total.turns;}
                }
                if(op==0x4011) {require(!movement,"overlapping_movement");movement=plain;++total.moves;}
                if(op==0x401c)ground[static_cast<std::int16_t>(read_le(View(plain).subspan(4,2)))]=plain.at(6);
                if(op==0x4017)explode(static_cast<std::int16_t>(read_le(View(plain).subspan(4,2))));
                if(op==0x40bd || op==0x40bf || op==0x40cc || op==0x40d5) {
                    require(actor==1,"unexpected_human_attack");++total.attacks;
                    require(plain.at(5)==255,"boss_attack_consumed_inventory");
                    if(op!=0x40bd)require(plain.at(8)==1 && plain.at(9)==0,"boss_projectile_not_actor_presentation");
                    const auto target=static_cast<std::int16_t>(read_le(View(plain).subspan(6,2)));
                    if(op==0x40bd)mines.push_back({target,1,3});
                    else {
                        const auto effect=op==0x40bf?RichonlineCombatEffect::missile:op==0x40cc?RichonlineCombatEffect::nuclear:RichonlineCombatEffect::safe_nuclear;
                        const auto footprint=richonline_attack_footprint(effect,target,static_cast<std::uint16_t>(topology.width()),static_cast<std::uint16_t>(topology.height()),combat);
                        for(const auto pos:footprint)ground.erase(pos);
                        std::vector<std::int16_t> roots;
                        for(const auto& mine:mines)if(std::find(footprint.begin(),footprint.end(),mine.position)!=footprint.end())roots.push_back(mine.position);
                        for(const auto pos:roots)explode(pos);
                    }
                }
                if(op==0x4022)++total.wealth;
                if(op==0x4023)++total.fortune;
                if(op==0x4096) {
                    ++total.chance;
                    const auto category=news.event(map_name,static_cast<std::int32_t>(read_le(View(plain).subspan(4,2)))).category;
                    if(category>=7 && category<=9) forced_step_turns[actor]=std::max(forced_step_turns[actor],
                        static_cast<std::uint8_t>((category==9?status_rules.turtle_turns:status_rules.fixed_step_turns)+1));
                }
                if(op==0x401b)terminal=true;
                last.push_back(std::move(plain));
            }
            if(plan.sent)plan.sent(frame);
        }
    }
    bool has(std::uint16_t op)const {return std::any_of(last.begin(),last.end(),[op](const auto& p){return code(p)==op;});}
    void send(Bytes bytes) {
        trace<<Json{{"direction","c2s"},{"opcode",code(bytes)},{"calendar",calendar},{"actor",actor},{"plain",bytes}}.dump()<<'\n';trace.flush();
        last_request=bytes;pending_property.reset();ingest(plan.message({},bytes));
    }
    void bank_exit() {
        auto bytes=request(0x27,calendar,2);bytes.insert(bytes.end(),{0xa5,0x5a});append_le(bytes,0,4);
        send(std::move(bytes));++total.banks;
    }
    void finish_move() {
        require(movement.has_value(),"movement_missing");
        const auto move=std::move(*movement);movement.reset();
        const auto before=calendar;const auto moving_actor=actor;
        auto position=static_cast<std::int16_t>(read_le(View(move).subspan(4,2)));
        std::vector<std::int16_t> route;
        std::uint8_t heading=0;
        for(std::size_t i=0;i<move.at(7);++i) {
            if(i!=0)if(const auto portal=topology.portal_destination(position))position=*portal;
            heading=static_cast<std::uint8_t>((move.at(11+i/4)>>(2*(i%4)))&3U);
            const auto next=topology.cell(position).neighbors[heading];require(next.has_value(),"wire_route_not_adjacent");
            position=*next;route.push_back(position);
        }
        require(!route.empty(),"empty_wire_route");
        for(std::size_t i=0;i+1<route.size();++i)if(topology.cell(route[i]).static_type==9) {
            send(request(0x28,calendar,static_cast<std::uint16_t>(route[i])));
            if(moving_actor==0 && has(0x4018) && !has(0x402a))bank_exit();
        }
        explode(position);
        const auto npc=ground.find(position);
        const auto picked=npc!=ground.end() && (npc->second<=7 || npc->second==9) ? std::optional{npc->second}:std::nullopt;
        if(picked)ground.erase(position);
        send(request(0x11,calendar,static_cast<std::uint16_t>(position)));
        positions[moving_actor]=position;
        if(picked) {++total.npc_pickups;if(*picked==9)++total.chest;}
        if(terminal || calendar!=before)return;
        if(moving_actor==0 && picked && (*picked==0 || *picked==1) && !has(0x4030) && !has(0x4018) && !pending_property)
            send(request(34,calendar,0xa501));
        for(unsigned decisions=0;decisions<5 && !terminal && calendar==before;++decisions) {
            if(has(0x4030)) {send(request(0x30,calendar,0xa5ff));++total.shops;continue;}
            if(has(0x4018) && !has(0x402a)) {bank_exit();continue;}
            if(pending_property) {
                const auto pending=*pending_property;
                if(pending==0x20) {
                    auto bytes=request(pending,calendar,0,4);bytes.insert(bytes.end(),{1,0xa5,0x5a,0xc3});send(std::move(bytes));
                } else if(pending==0x37)send(request(pending,calendar,0xa50b));
                else if(pending==0x38) {
                    send(request(pending,calendar,0xa501));
                    if(calendar==before && has(0x403e) && !terminal) pending_property=0x39;
                }
                else if(pending==0x39) {send(request(pending,calendar,0xa501));++total.research;}
                else throw std::runtime_error("unexpected_property_decision");
                ++total.properties;continue;
            }
            const auto& cell=topology.cell(position);
            const auto degree=std::count_if(cell.neighbors.begin(),cell.neighbors.end(),[](const auto& x){return x.has_value();});
            if(moving_actor==0 && degree>2) {
                std::uint8_t selected=255;
                for(std::uint8_t dir=0;dir<4;++dir)if(dir!=(heading+2U)%4U && cell.neighbors[dir]) {selected=dir;break;}
                require(selected!=255,"junction_has_no_forward_edge");send(request(0x34,calendar,0xa500U+selected));++total.junctions;continue;
            }
            throw std::runtime_error("landing_did_not_reach_known_wait_or_next_turn");
        }
        require(terminal || calendar!=before,"landing_decision_loop_limit");
    }
    void run(unsigned limit,std::uint8_t expected_boss_dice) {
        ingest(plan.admitted());send(Bytes{0,0});
        require(actor==1 && movement && movement->at(6)==expected_boss_dice,"stage_boss_opening_dice_or_first_actor_wrong");
        while(turns<limit && !terminal) {
            if(movement)finish_move();
            else {
                require(actor==0,"boss_turn_missing_movement");
                if(human_rolls==0) {
                    const auto before=storage.game_account_for_role(role).gold;
                    send(Bytes{103,0,static_cast<std::uint8_t>(calendar),static_cast<std::uint8_t>(calendar>>8),0,0,1,0xa5,0,0,0,0});
                    require(has(0x40b7) && movement && movement->at(7)==1,"initial_controlled_card_failed");
                    require(storage.game_account_for_role(role).gold==before,"initial_card_wrongly_charged_gold");
                    ++total.controlled_cards;
                } else if(human_rolls<=3) {
                    const auto dice=human_rolls==1?2U:human_rolls==2?3U:1U;
                    const auto before=storage.game_account_for_role(role).gold;
                    send(request(0x14,calendar,0xa500U+dice));
                    require(last.empty() && storage.game_account_for_role(role).gold==before,"dice_selection_not_silent_or_charged_early");
                    send(request(0x10,calendar,0,4));
                    const auto effective=forced_step_turns[actor]?1U:dice;
                    const auto cost=effective==2?160U:effective==3?240U:0U;
                    require(movement && movement->at(6)==effective && read_le(View(*movement).subspan(24,4))==cost,"selected_dice_wire_cost_mismatch");
                    require(storage.game_account_for_role(role).gold==before-cost,"selected_dice_persistent_charge_mismatch");
                    trace<<Json{{"event","dice_charge_verified"},{"dice",dice},{"effective_dice",effective},
                        {"forced_step_turns",forced_step_turns[actor]},{"cost",cost},{"gold_before",before},
                        {"gold_after",storage.game_account_for_role(role).gold}}.dump()<<'\n';
                    ++total.selected_dice;
                } else send(request(0x10,calendar,0,4));
                ++human_rolls;require(movement.has_value() || terminal,"roll_did_not_return_movement");
            }
        }
        if(terminal) {
            const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds{8};
            while(!plan.game_finished() && std::chrono::steady_clock::now()<deadline)std::this_thread::sleep_for(std::chrono::milliseconds{20});
            require(plan.game_finished(),"terminal_never_ready_for_lobby_return");
            plan.lobby_sent(richonline_lobby_game_finished(3));require(!plan.game_finished(),"lobby58_not_checkpointed");++total.returns;
            trace<<Json{{"event","lobby58_confirmed"},{"transport","serialized callback; lobby socket outside harness"}}.dump()<<'\n';
        }
    }
};
}

int main(int argc,char** argv) {
    try {
        require(argc==4 || argc==5,"usage: resources bootstrap output-directory [level]");
        const std::filesystem::path resources=std::filesystem::absolute(argv[1]);
        const std::filesystem::path bootstrap=std::filesystem::absolute(argv[2]);
        const std::filesystem::path output=std::filesystem::absolute(argv[3]);
        std::filesystem::create_directories(output);
        const auto chance=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(resources));
        const auto news=RichonlineChanceEventTable::load(resources);
        const auto status=RichonlineStatusRules::load(resources);
        const auto decoded=[&](const char* name) {const auto bytes=load_original_kpd(resources/"Data"/name,8U*1024U*1024U);return std::string(bytes.begin(),bytes.end());};
        const auto combat=RichonlineCombatResources::parse(decoded("Prop.kpd"),decoded("Npc.kpd"),decoded("GValue.kpd"));
        const unsigned first=argc==5?static_cast<unsigned>(std::stoul(argv[4])):2U;
        const unsigned final=argc==5?first:4U;
        for(unsigned level=first;level<=final;++level) {
            const auto name="BS_1_"+std::to_string(level)+".emp";
            const auto& package=find_richonline_map_package(name,0);
            const auto rules=load_richonline_map_rule_resources(resources,package,0);
            require(package.readiness==RichonlineMapReadiness::partial,"package_readiness_overclaimed");
            require(package.closed_chance && package.closed_npcs && package.combat && package.opening_hand,"package_policy_missing");
            require(package.raw_status_policy==RichonlineMapRawStatusPolicy::closed_boss_initial_status,"raw_authority_missing");
            require(rules.stage.map_id==10+level && rules.stage.boss.role==0 && rules.stage.boss.equipment[6]==31,"selected_boss_identity_wrong");
            const auto expected_cash=level==2?100000U:level==3?120000U:150000U;
            const auto expected_human_cash=level==2?15000U:level==3?20000U:18000U;
            require(rules.stage.boss.base_cash==expected_cash && rules.stage.boss.max_dice==(level==2?2:3),"per_stage_difficulty_lost");
            require(rules.stage.human.cash==expected_human_cash && rules.stage.human.tickets==300,"per_stage_human_funds_lost");
            require(rules.conservative_spawns.has_value() && rules.initial_npcs.empty(),"map_resource_spawn_or_npc_changed");
            const auto policy=package.configure({"unrelated.emp",999,999,{0xa5,0x5a}});
            require(policy.map_name==name && policy.event_id==17 && policy.card_id==1038 && policy.opaque6_7==std::array<std::uint8_t,2>{0xa5,0x5a},"map_card_policy_inherited_foreign_identity");
            RichonlineBossCards cards(chance,7,policy);
            cards.configure_tile_rewards(package.closed_chance->playable_reward_cards,[](std::size_t){return std::size_t{0};});
            require(cards.tile_reward_cards()==package.closed_chance->playable_reward_cards,"playable_pool_missing_source_card");
            const auto chance_policy=make_richonline_closed_chance_policy(news,name,package.closed_chance->playable_reward_cards,true,{0xa5,0x5a});
            for(const auto& cell:rules.topology.cells()) if(cell.walkable)
                require(richonline_map_static_rule(cell).effect!=RichonlineMapStaticEffect::unsupported &&
                        richonline_map_static_rule(cell).effect!=RichonlineMapStaticEffect::pending_server_reward,"map_has_unclosed_static");
            for(const std::int8_t type:std::array<std::int8_t,3>{68,69,70}) for(std::uint8_t actor=0;actor<2;++actor) {
                const RichonlineLandingContext context{actor,100,type,-1,3,actor==1,2,false,{}};
                for(const bool last:{false,true}) {
                    const auto attempt=prepare_richonline_chance_landing(news,*chance,status,chance_policy,context,7,
                        {{30000,0,300,std::nullopt},0},{},[last](std::size_t count){return last?count-1:0;});
                    require(attempt.disposition==RichonlineChanceLandingDisposition::prepared && attempt.prepared.has_value(),"chance_color_has_no_closed_event");
                }
            }
            const auto fixture=output/(name+"-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())+".sqlite3");
            Storage storage(fixture,ClientProfile::richonline);
            const auto actor=storage.dispatch("accounts.create",{{"username","multi-fixture"},{"password","local-only"}}).at("account").at("role_id").get<std::uint32_t>();
            Totals totals;std::optional<std::uint16_t> pending_property;
            unsigned opponent_properties=0,temple_landings=0,graceful_exits=0;
            std::vector<Json> diagnostics;
            std::ofstream trace(output/(name+".trace.jsonl"));require(trace.good(),"trace_open_failed");
            auto runtime=load_richonline_boss_runtime(storage,bootstrap,[&](const std::string& event,const Json& values) {
                if(event=="richonline_property_landed") {
                    if(values.at("pending_opcode").get<unsigned>()!=0)
                        pending_property=values.at("pending_opcode").get<std::uint16_t>();
                    const auto owner=values.at("owner").get<unsigned>();
                    if(owner<2 && owner!=values.at("actor_slot").get<unsigned>()) ++opponent_properties;
                    if(values.at("building_kind")==16) ++temple_landings;
                    trace<<Json{{"event",event},{"values",values}}.dump()<<'\n';
                }
                const bool expected_cleanup=event=="richonline_terminal_cleanup" && values.value("reason","")=="game_connection_closed";
                if(values.value("level","")=="warning" && !expected_cleanup)
                    diagnostics.push_back({{"event",event},{"values",values}});
            });
            require(runtime.has_value(),"runtime_not_loaded");
            const auto prebuilt_count=std::count_if(rules.properties.properties.begin(),rules.properties.properties.end(),
                [](const auto& property){return property.level>0;});
            require(prebuilt_count==2,"prebuilt_count_changed");
            trace<<Json{{"event","resource_verified"},{"map",name},{"cash",rules.stage.boss.base_cash},{"dice",rules.stage.boss.max_dice},
                {"human_cash",rules.stage.human.cash},{"events",news.size(name)},{"closed_events",chance_policy.entries.size()},
                {"playable_reward_cards",cards.tile_reward_cards()},{"prebuilt_count",prebuilt_count},{"source_card_rows",rules.card_weights.size()}}.dump()<<'\n';
            for(unsigned session=0;session<3;++session) {
                const auto losses_before=storage.roles_for_username("multi-fixture").at(0).at("losses").get<std::uint32_t>();
                auto plans=runtime->provider(19001,make_room(resources,actor,name));require(plans.size()==1,"missing_plan");
                auto transport=std::make_unique<TcpPlan>(plans.front());
                Driver driver{transport->facade,rules.topology,totals,pending_property,combat,trace,storage,actor,news,name,status};
                driver.positions={rules.conservative_spawns->at(0).position,rules.conservative_spawns->at(1).position};
                try {
                    driver.run(level==3?320U:160U,static_cast<std::uint8_t>(rules.stage.boss.max_dice));
                    if(!driver.terminal) {
                        driver.send(Bytes{0x0a,0x00});
                        require(driver.has(0x4006),"map_graceful_leave_ack_missing");
                        ++graceful_exits;
                    }
                }
                catch(const std::exception& error) {
                    std::cerr<<Json{{"event","driver_failed"},{"map",name},{"session",session},{"calendar",driver.calendar},
                        {"actor",driver.actor},{"positions",driver.positions},{"last_request",driver.last_request},
                        {"last_response",driver.last},{"reason",error.what()},{"diagnostics",diagnostics},
                        {"transport_logs",transport->logs()},{"totals",totals.json()}}.dump()<<'\n';
                    transport.reset();plans.front().disconnected();throw;
                }
                transport.reset();plans.front().disconnected();
                if(!driver.terminal)
                    require(storage.roles_for_username("multi-fixture").at(0).at("losses").get<std::uint32_t>()==losses_before+1,
                        "map_graceful_leave_loss_not_exactly_once");
                require(storage.pending_game_settlements("multi-fixture",actor).empty(),"terminal_database_outbox_pending");
                std::cout<<Json{{"event","session_complete"},{"map",name},{"session",session},{"terminal",driver.terminal},{"totals",totals.json()}}.dump()<<'\n';
            }
            require(totals.turns>=40 && totals.attacks>0 && totals.controlled_cards>0 && totals.selected_dice>=3,"insufficient_map_runtime_coverage");
            require(totals.returns+graceful_exits==3 && opponent_properties>0,"map_exit_or_opponent_property_coverage_missing");
            require(diagnostics.empty(),"map_runtime_warnings");
            std::cout<<Json{{"event","map_pass"},{"map",name},{"transport","encrypted GameService TCP"},{"totals",totals.json()},
                {"opponent_property_landings",opponent_properties},{"temple_landings",temple_landings},{"graceful_exits",graceful_exits},
                {"database",utf8(fixture)},{"client_ui_verified",false},{"live_data_touched",false}}.dump()<<'\n';
        }
    } catch(const std::exception& error) {std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
    return 0;
}

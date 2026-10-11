#include "richonline_classic_session.hpp"
#include "richonline_boss_landing.hpp"
#include "richonline_junction.hpp"
#include "richonline_shop_catalog.hpp"

#include <algorithm>
#include <deque>
#include <limits>
#include <utility>

namespace richnet {
namespace {
enum class Phase { loading,roll,moving,property,event,junction,closed };
struct Retired {
    std::uint8_t actor;
    Bytes request;
};
struct Session {
    RichonlineClassicStartup startup;
    RichonlineClassicSessionRules rules;
    RichonlineClassicWorld world;
    RichonlineClassicServices services;
    RichonlineBoardInit board;
    std::vector<RichonlineActorStatus> statuses;
    std::vector<std::uint8_t> dice;
    RichonlinePlayerOpeningHands opening_hands;
    RichonlineJunction junction;
    RichonlineRoute route;
    Phase phase=Phase::loading;
    std::uint8_t actor;
    std::uint16_t calendar;
    std::uint64_t sequence=0,completed_rounds=0,movement_sequence=0;
    std::optional<std::uint16_t> pending_opcode;
    std::optional<RichonlineSharedMovementWait> movement;
    std::deque<Retired> retired;
    std::vector<bool> disconnected;

    Session(const RichonlineClassicStartup& source,RichonlineClassicSessionRules policy)
        :startup(source),rules(std::move(policy)),board(first_board(source)),
         statuses(board.participants.size()),dice(rules.maximum_dice),
         junction(board.game_server_id),actor(rules.first_actor),
         calendar(static_cast<std::uint16_t>(source.recipients.front().snapshot.calendar_counter)),
         disconnected(board.participants.size(),false) {
        const auto count=board.participants.size();
        if(count<2 || count>4 || source.players.size()!=count || source.recipients.size()!=count ||
            actor>=count || dice.size()!=count || rules.opening_hands.size()!=count ||
            !rules.random || !rules.now || !rules.card_resources || !rules.resale || !rules.services ||
            rules.decision_timeout<std::chrono::milliseconds{1000} || rules.decision_timeout>std::chrono::minutes{5} ||
            rules.route_wire.local_reserve_charge!=0)
            throw CodecError("richonline_classic_session_policy_invalid");
        const auto& snapshot=source.recipients.front().snapshot;
        if(snapshot.slots.size()!=count || snapshot.game_server_id!=board.game_server_id)
            throw CodecError("richonline_classic_session_snapshot_invalid");
        const auto expected_snapshot=encode_richonline_board_snapshot(snapshot);
        const auto expected_init=encode_richonline_board_init(board);
        std::vector<RichonlineGameFunds> funds;
        for(std::size_t index=0;index<count;++index) {
            auto init=source.recipients[index].init;
            if(init.local_slot!=index || source.recipients[index].connection!=source.players[index].connection ||
                source.players[index].identity!=board.participants[index].lobby_identity || dice[index]<1 || dice[index]>3)
                throw CodecError("richonline_classic_session_player_mismatch");
            init.local_slot=board.local_slot;
            if(encode_richonline_board_init(init)!=expected_init ||
                encode_richonline_board_snapshot(source.recipients[index].snapshot)!=expected_snapshot)
                throw CodecError("richonline_classic_session_boards_differ");
            const auto& person=board.participants[index];
            if(!source.topology.cell(person.position).walkable || person.direction>3)
                throw CodecError("richonline_classic_session_spawn_invalid");
            const auto& money=snapshot.slots[index];
            funds.push_back({money.cash,money.deposit,money.tickets,{}});
            // NEW初始化附身槽的有符号-1；optional空值表示未知，不能用于地产资格判断。
            statuses[index].possession=-1;
        }
        world.ledger=std::make_shared<RichonlineGameLedger>(std::move(funds));
        world.property=std::make_shared<RichonlineClassicProperty>(board.game_server_id,source.topology,
            source.properties,world.ledger,rules.now,rules.decision_timeout,rules.script);
        opening_hands=prepare_richonline_player_opening_hands(board.game_server_id,rules.opening_hands,*rules.card_resources);
        for(std::uint8_t slot=0;slot<count;++slot) {
            auto cards=std::make_shared<RichonlinePlayerCards>(rules.card_resources,board.game_server_id,source.map_name,slot,0);
            cards->configure_tile_rewards(rules.random_reward_cards,rules.random,*rules.resale);
            world.cards.push_back(std::move(cards));
        }
        services=rules.services(world);
        if(!services.landing || !services.property_effects || !services.event || !services.poll) {
            release_members();
            throw CodecError("richonline_classic_session_services_incomplete");
        }
    }
    ~Session() { release_members(); }
    void release_members() noexcept {
        for(std::uint8_t slot=0;slot<disconnected.size();++slot)
            try { disconnect(slot); } catch(...) {}
    }
    static RichonlineBoardInit first_board(const RichonlineClassicStartup& source) {
        if(source.recipients.empty()) throw CodecError("richonline_classic_session_players_missing");
        return source.recipients.front().init;
    }
    RichonlineClassicTurnContext context(std::optional<std::int16_t> position={}) const {
        const auto tile=position.value_or(board.participants[actor].position);
        const auto& cell=startup.topology.cell(tile);
        std::uint8_t degree=0;
        for(const auto& neighbor:cell.neighbors) if(neighbor) ++degree;
        bool occupied=false;
        for(std::size_t other=0;other<board.participants.size();++other)
            if(other!=actor && board.participants[other].position==tile) occupied=true;
        return {board.game_server_id,calendar,sequence,completed_rounds,
            {actor,tile,cell.static_type,cell.property_ref,0,false,degree,occupied,statuses[actor],false},
            board.participants,statuses};
    }
    Bytes stop() const {
        Bytes packet;append_le(packet,0x4013,2);append_le(packet,board.game_server_id,2);
        append_le(packet,static_cast<std::uint16_t>(board.participants[actor].position),2);
        return packet;
    }
    static void append(std::vector<Bytes>& into,std::vector<Bytes> from) {
        into.insert(into.end(),std::make_move_iterator(from.begin()),std::make_move_iterator(from.end()));
    }
    void remember(std::uint8_t sender,View request) {
        retired.push_back({sender,Bytes(request.begin(),request.end())});
        if(retired.size()>64) retired.pop_front();
    }
    bool was_retired(std::uint8_t sender,View request) const {
        return std::any_of(retired.begin(),retired.end(),[&](const auto& entry) {
            return entry.actor==sender && std::ranges::equal(entry.request,request);
        });
    }
    void healthy() const {
        if(phase==Phase::closed) throw CodecError("richonline_classic_session_closed");
    }
    std::vector<Bytes> begin_turn() {
        if(sequence==std::numeric_limits<std::uint64_t>::max())
            throw CodecError("richonline_classic_turn_sequence_overflow");
        // 每条非重播4010加一次日历WORD；轮数只在完整绕回显式起始槽后加一。
        auto packet=encode_richonline_turn4010({board.game_server_id,static_cast<std::int8_t>(actor),
            static_cast<std::int8_t>(rules.first_actor),0},rules.opaque_turn7);
        ++sequence;calendar=static_cast<std::uint16_t>(calendar+1U);
        richonline_status_begin_active_turn(statuses[actor]);
        phase=Phase::roll;pending_opcode.reset();
        if(rules.log) rules.log("richonline_classic_turn actor="+std::to_string(actor)+
            " sequence="+std::to_string(sequence)+" calendar="+std::to_string(calendar));
        return {std::move(packet)};
    }
    std::vector<Bytes> opening() {
        if(phase!=Phase::loading) throw CodecError("richonline_classic_opening_repeated");
        auto messages=opening_hands.synchronization;
        append(messages,begin_turn());
        for(std::size_t slot=0;slot<world.cards.size();++slot)
            world.cards[slot]->commit_inventory(opening_hands.inventories[slot]);
        return messages;
    }
    std::vector<Bytes> advance(std::vector<Bytes> messages) {
        const auto next=static_cast<std::uint8_t>((actor+1U)%board.participants.size());
        // 月数在客户端转为BYTE天数；结算业务尚未装配时明确停在边界，不无限续局。
        const auto limit=static_cast<std::uint8_t>(startup.game_months*30U);
        if(next==rules.first_actor && limit && completed_rounds+2>limit)
            throw CodecError("richonline_classic_month_settlement_unimplemented");
        richonline_status_finish_previous_turn(statuses[actor]);
        actor=next;
        if(actor==rules.first_actor) ++completed_rounds;
        append(messages,begin_turn());return messages;
    }
    std::vector<Bytes> complete(std::vector<Bytes> messages) {
        const auto& person=board.participants[actor];
        if(junction.begin(startup.topology,{person.position,person.direction,calendar},rules.now())) {
            phase=Phase::junction;pending_opcode=0x34;return messages;
        }
        return advance(std::move(messages));
    }
    std::vector<Bytes> accept_result(RichonlineLandingResult result) {
        // 结算须由完整经典结算模块持久化并驱动投递；此回合骨架不伪造finished。
        if(result.progress==RichonlineLandingProgress::finished || result.temple_change)
            throw CodecError("richonline_classic_continuation_unimplemented");
        if(result.progress!=RichonlineLandingProgress::complete && result.progress!=RichonlineLandingProgress::await_event)
            throw CodecError("richonline_classic_continuation_invalid");
        if((result.progress==RichonlineLandingProgress::await_event)!=result.pending_opcode.has_value())
            throw CodecError("richonline_classic_continuation_invalid");
        if(result.pending_opcode && (*result.pending_opcode==0x10 || *result.pending_opcode==0x11 ||
            *result.pending_opcode==0x14 || *result.pending_opcode==0x20 || *result.pending_opcode==0x21 ||
            *result.pending_opcode==0x34))
            throw CodecError("richonline_classic_continuation_reserved_opcode");
        if(result.status_change) {
            if(result.status_change->expected!=statuses[actor])
                throw CodecError("richonline_classic_continuation_status_stale");
            // 冰冻、梦游及炸弹需要各自回合/途中阶段，未接入前不能只写状态再普通掷骰。
            if(result.status_change->updated!=statuses[actor])
                throw CodecError("richonline_classic_status_continuation_unimplemented");
        }
        if(result.progress==RichonlineLandingProgress::await_event) {
            phase=Phase::event;pending_opcode=result.pending_opcode;return std::move(result.messages);
        }
        return complete(std::move(result.messages));
    }
    RichonlineClassicPropertyEntry property_entry() const {
        const auto current=context();
        const auto land=startup.players[actor].equipment[2];
        if(land>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
            throw CodecError("richonline_classic_land_equipment_invalid");
        return {board.game_server_id,calendar,sequence,actor,current.landing.position,
            current.landing.property_ref,static_cast<std::int32_t>(land),statuses[actor],false};
    }
    std::vector<Bytes> property_effects(std::vector<Bytes> prefix) {
        auto result=services.property_effects(context());
        prefix.insert(prefix.end(),std::make_move_iterator(result.messages.begin()),std::make_move_iterator(result.messages.end()));
        result.messages=std::move(prefix);return accept_result(std::move(result));
    }
    std::vector<Bytes> land() {
        const auto current=context();
        // 先给业务处理碰撞/特殊类型。基础分支不假定多人同格时没有库存或附身交换。
        if(auto result=services.landing(current)) return accept_result(std::move(*result));
        if(current.landing.occupied_by_other_actor)
            throw CodecError("richonline_classic_collision_unimplemented");
        if(current.landing.property_ref>=0) {
            const auto property=world.property->snapshot(current.landing.property_ref);
            if(property.kind!=0 && property.kind!=1)
                throw CodecError("richonline_classic_property_landing_unimplemented");
            if(property.owner && *property.owner!=actor)
                throw CodecError("richonline_classic_rent_unimplemented");
            const bool purchase=!property.owner;
            auto entry=property_entry();
            std::uint32_t cost=purchase ? property.price : property.sprite_type==11 ? 500U : 1500U;
            if(entry.land_equipment>0) cost/=2;
            const bool eligible=purchase || (property.kind!=1 && property.level<5);
            if(eligible && world.ledger->snapshot(actor).funds.cash>cost) {
                auto packet=stop();
                pending_opcode=world.property->begin(purchase ? RichonlineClassicPropertyChoice::purchase :
                    RichonlineClassicPropertyChoice::upgrade,entry);
                phase=Phase::property;return {std::move(packet)};
            }
            return property_effects({stop()});
        }
        if(auto prepared=world.cards[actor]->prepare_landing(current.landing)) {
            auto result=std::move(prepared->result);
            world.cards[actor]->commit_landing(*prepared);
            return accept_result(std::move(result));
        }
        if(current.landing.static_type!=-1)
            throw CodecError("richonline_classic_static_landing_unimplemented");
        return complete({stop()});
    }
    struct PreparedMove { RichonlineRoute route;Bytes packet; };
    PreparedMove prepare_move(std::optional<std::uint8_t> selected={}) {
        const auto count=selected ? std::uint8_t{1} : dice[actor];
        std::array<std::int8_t,3> faces{1,rules.inactive_ui_dice[0],rules.inactive_ui_dice[1]};
        std::int32_t budget=0;
        for(std::uint8_t index=0;index<count;++index) {
            const auto choice=selected ? static_cast<std::size_t>(*selected-1U) : rules.random(6);
            if(choice>=6) throw CodecError("richonline_classic_die_invalid");
            faces[index]=static_cast<std::int8_t>(choice+1);budget+=faces[index];
        }
        const auto& person=board.participants[actor];
        auto proposed=build_richonline_route(startup.topology,{person.position,person.direction,budget,{}},rules.random);
        // 途经银行会产生0028，末端传送会改变落点；接通专用阶段前不可发布虚假的0011等待。
        if(startup.topology.cell(proposed.landings.back()).static_type==61)
            throw CodecError("richonline_classic_portal_landing_unimplemented");
        std::vector<RichonlineMoveDirection> directions;
        for(const auto direction:proposed.directions) directions.push_back(static_cast<RichonlineMoveDirection>(direction));
        auto packet=encode_richonline_route4011({board.game_server_id,person.position,count,faces,
            std::move(directions),proposed.landings.size()},rules.route_wire);
        if(movement_sequence==std::numeric_limits<std::uint64_t>::max())
            throw CodecError("richonline_classic_movement_sequence_overflow");
        return {std::move(proposed),std::move(packet)};
    }
    void commit_move(PreparedMove move) {
        route=std::move(move.route);
        movement=RichonlineSharedMovementWait{++movement_sequence,calendar,route.landings.back(),actor};
        phase=Phase::moving;
    }
    std::vector<Bytes> action(std::uint8_t sender,View request) {
        healthy();
        if(request.size()<4 || sender>=board.participants.size())
            throw CodecError("richonline_classic_request_invalid");
        const auto opcode=read_le(request.first(2));
        // 本期日历优先处理；原协议没有请求序号，历史字节相同不能抢先吞掉新操作。
        if(read_le(request.subspan(2,2))!=calendar) {
            if(was_retired(sender,request)) return {};
            throw CodecError("richonline_classic_calendar_mismatch");
        }
        // 0014由每个客户端自己的骰数界面产生，可能在别人的回合刷新；只改发送者偏好。
        // 它不是掷骰授权，不能因为当前行动者不同而改到别人的骰数或断开整局。
        if(opcode==0x14 && phase!=Phase::loading) {
            const auto choice=std::get<RichonlineDiceChoice14>(parse_richonline_movement_request(request));
            if(choice.count>rules.maximum_dice[sender]) throw CodecError("richonline_classic_dice_not_available");
            dice[sender]=choice.count;return {};
        }
        if(sender!=actor) throw CodecError("richonline_classic_sender_not_active");
        if(phase==Phase::roll) {
            if(opcode==0x32) {
                const auto discard=parse_richonline_card_discard50(request);
                auto prepared=world.cards[actor]->prepare_discard(discard,static_cast<std::int8_t>(actor));
                auto messages=std::vector<Bytes>{std::move(prepared.confirmation4033)};
                world.cards[actor]->commit_inventory(prepared.remaining_inventory);return messages;
            }
            if(opcode==103) {
                const auto use=std::get<RichonlineCardDiceRequest103>(parse_richonline_controlled_dice_request(request));
                const auto prepared=world.cards[actor]->prepare_use(use);
                if(!prepared) return {encode_richonline_dice_recovery400b(board.game_server_id)};
                auto move=prepare_move(prepared->die);
                std::vector<Bytes> messages{prepared->confirmation40b7,std::move(move.packet)};
                remember(sender,request);world.cards[actor]->commit_use(*prepared);commit_move(std::move(move));return messages;
            }
            if(opcode==0x10) {
                const auto roll=std::get<RichonlineMoveRequest10>(parse_richonline_movement_request(request));
                if(roll.parameter!=0) throw CodecError("richonline_classic_roll_parameter_unsupported");
                auto move=prepare_move();std::vector<Bytes> messages{std::move(move.packet)};
                remember(sender,request);commit_move(std::move(move));return messages;
            }
        }
        if(phase==Phase::moving && opcode==0x11) {
            const auto stop_request=std::get<RichonlineMoveStop11>(parse_richonline_movement_request(request));
            if(!movement || stop_request.endpoint!=movement->endpoint)
                throw CodecError("richonline_classic_endpoint_mismatch");
            remember(sender,request);
            board.participants[actor].position=route.landings.back();
            board.participants[actor].direction=route.directions.back();
            movement.reset();route={};return land();
        }
        if(phase==Phase::property && pending_opcode==opcode) {
            auto result=world.property->handle(sender,request,property_entry());
            remember(sender,request);pending_opcode.reset();return property_effects({std::move(result.message)});
        }
        if(phase==Phase::junction && opcode==0x34) {
            auto result=junction.decide(request,rules.now());remember(sender,request);
            board.participants[actor].direction=result.heading;return advance({std::move(result.response)});
        }
        if(phase==Phase::event && pending_opcode==opcode) {
            auto result=services.event(context(),request);remember(sender,request);return accept_result(std::move(result));
        }
        if(was_retired(sender,request)) return {};
        throw CodecError("richonline_classic_action_out_of_phase");
    }
    std::vector<Bytes> poll() {
        healthy();
        if(phase==Phase::property) {
            if(auto result=world.property->poll(property_entry())) {
                pending_opcode.reset();return property_effects({std::move(result->message)});
            }
        } else if(phase==Phase::junction) {
            if(auto result=junction.poll(rules.now())) {
                board.participants[actor].direction=result->heading;return advance({std::move(result->response)});
            }
        } else if(phase==Phase::event) {
            if(auto result=services.poll(context())) return accept_result(std::move(*result));
        }
        return {};
    }
    void disconnect(std::uint8_t sender) {
        if(sender>=disconnected.size() || disconnected[sender]) return;
        disconnected[sender]=true;phase=Phase::closed;movement.reset();
        if(services.disconnected) services.disconnected(sender);
    }
};
RichonlineSharedMessages broadcast(std::vector<Bytes> packets) {
    RichonlineSharedMessages messages;messages.reserve(packets.size());
    for(auto& packet:packets) messages.push_back({{},std::move(packet)});
    return messages;
}
}
RichonlineSharedCallbacks make_richonline_classic_session(const RichonlineClassicStartup& startup,
    RichonlineClassicSessionRules rules) {
    auto session=std::make_shared<Session>(startup,std::move(rules));
    RichonlineSharedCallbacks callbacks;
    callbacks.opening=[session] {return broadcast(session->opening());};
    callbacks.action=[session](std::uint8_t actor,const Envelope299&,View request) {
        return broadcast(session->action(actor,request));
    };
    callbacks.poll=[session] {return broadcast(session->poll());};
    callbacks.disconnected=[session](std::uint8_t actor) {session->disconnect(actor);};
    callbacks.retired_action=[session](std::uint8_t actor,View request) {return session->was_retired(actor,request);};
    callbacks.movement_wait=[session] {return session->movement;};
    return callbacks;
}
}

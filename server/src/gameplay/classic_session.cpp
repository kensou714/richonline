#include "richonline_classic_session.hpp"
#include "richonline_boss_landing.hpp"
#include "richonline_junction.hpp"
#include "richonline_shop_catalog.hpp"
#include "richonline_collision.hpp"
#include "richonline_raw_authority.hpp"
#include "richonline_rent_transfer.hpp"
#include "richonline_game_end.hpp"
#include "richonline_classic_terminal.hpp"
#include "richonline_portal_landing.hpp"
#include "lua_server.hpp"

#include <algorithm>
#include <bit>
#include <deque>
#include <limits>
#include <utility>

namespace richnet {
namespace {
enum class Phase { loading,roll,stationary,moving,bank,property,rent_transfer,event,junction,settling,closed };
struct Retired {
    std::uint8_t actor;
    Bytes request;
};
struct PendingRentTransfer {
    RichonlineRentTransferState state;
    RichonlineClassicPropertyState property;
    std::int16_t position;
    std::uint64_t sequence;
    std::chrono::steady_clock::time_point deadline;
};
struct PreparedRetirement {
    RichonlineClassicProperty::Retirement property;
    std::optional<RichonlineStockMarket::Retirement> stocks;
};
struct Session {
    RichonlineClassicStartup startup;
    RichonlineClassicSessionRules rules;
    RichonlineClassicWorld world;
    RichonlineClassicServices services;
    RichonlineBoardInit board;
    std::vector<RichonlineActorStatus> statuses;
    std::vector<std::uint8_t> active;
    std::vector<std::uint8_t> dice;
    RichonlinePlayerOpeningHands opening_hands;
    RichonlineJunction junction;
    RichonlineRoute route;
    std::unique_ptr<RichonlineRawAuthority> raw;
    bool collision_pending=false;
    std::unique_ptr<RichonlineGameBank> bank;
    std::optional<RichonlineGameFundsSnapshot> bank_funds;
    std::optional<std::size_t> bank_checkpoint;
    std::size_t route_cursor=0;
    Phase phase=Phase::loading;
    std::uint8_t actor,round_anchor;
    std::uint16_t calendar;
    std::uint64_t sequence=0,completed_rounds=0,movement_sequence=0;
    std::optional<std::uint16_t> pending_opcode;
    std::optional<RichonlineSharedMovementWait> movement;
    std::deque<Retired> retired;
    std::deque<std::pair<std::uint8_t,std::uint16_t>> retired_banks;
    std::optional<PendingRentTransfer> rent_transfer;
    std::deque<std::pair<std::uint8_t,std::uint16_t>> retired_rent_transfers;
    std::vector<bool> disconnected;
    std::unique_ptr<RichonlineClassicTerminal> terminal;
    std::vector<Bytes> stock_opening;
    std::uint32_t news_fines=richonline_classic_initial_news_fines;

    Session(const RichonlineClassicStartup& source,RichonlineClassicSessionRules policy)
        :startup(source),rules(std::move(policy)),board(first_board(source)),
         statuses(board.participants.size()),active(board.participants.size(),1),dice(rules.maximum_dice),
         junction(board.game_server_id),actor(rules.first_actor),round_anchor(rules.first_actor),
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
        if(rules.news) {
            if(!rules.news->select)
                throw CodecError("richonline_classic_news_policy_invalid");
        }
        raw=std::make_unique<RichonlineRawAuthority>(static_cast<std::uint8_t>(count),board.game_server_id);
        raw->initialize_game();
        for(std::uint8_t slot=0;slot<count;++slot) raw->initialize_actor(slot);
        world.property=std::make_shared<RichonlineClassicProperty>(board.game_server_id,source.topology,
            source.properties,world.ledger,rules.now,rules.decision_timeout,rules.script);
        if(rules.stocks) {
            const auto& policy=*rules.stocks;
            if(!policy.resources) throw CodecError("richonline_classic_stock_resources_missing");
            auto opening=prepare_richonline_stock_opening(board.game_server_id,*policy.resources,source.stocks,
                policy.history,policy.previous_index,policy.current_index,policy.factor,world.ledger,rules.script);
            world.stocks=std::move(opening.market);stock_opening=std::move(opening.messages);
        }
        if(rules.bank_wire) bank=std::make_unique<RichonlineGameBank>(board.game_server_id,
            *rules.bank_wire,rules.now,rules.script);
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
        try {
            if(rules.settlement) {
                terminal=rules.settlement(world);
                if(!terminal)throw CodecError("richonline_classic_terminal_missing");
                terminal->validate_identity(board.game_server_id,startup.room.key,count,startup.pawn_gold,world.ledger.get());
            }
        } catch(...) {release_members();throw;}
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
            if(other!=actor && active[other] && board.participants[other].position==tile) occupied=true;
        return {board.game_server_id,calendar,sequence,completed_rounds,
            {actor,tile,cell.static_type,cell.property_ref,0,false,degree,occupied,statuses[actor],false,collision_pending},
            board.participants,statuses,active};
    }
    std::vector<RichonlineCollisionActor> collision_actors() const {
        const auto scripted=raw->game().scripted_event83830;
        if(!scripted || *scripted!=-1) throw CodecError("richonline_classic_collision_game_unavailable");
        std::vector<RichonlineCollisionActor> actors;
        actors.reserve(board.participants.size());
        for(std::uint8_t slot=0;slot<board.participants.size();++slot) {
            const auto& state=raw->actor(slot);
            const auto possession=statuses[slot].possession;
            if(!state.kidnapped1497 || !possession || *possession< -1 || *possession>32)
                throw CodecError("richonline_classic_collision_actor_unknown");
            // 碰撞核心的nullopt约定为无附身；在适配层先证明原始值确为-1，
            // 不能把回合状态中的未知optional直接当作无附身。
            actors.push_back({slot,board.participants[slot].position,active[slot]!=0,false,*state.kidnapped1497!=-1,
                *possession==-1 ? std::nullopt : possession,world.cards[slot]->inventory()});
        }
        return actors;
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
        if(request.size()>=2 && read_le(request.first(2))==0x76) {
            const auto choice=decode_richonline_rent_transfer_choice(request);
            if(std::ranges::find(retired_rent_transfers,std::pair{sender,choice.calendar})!=retired_rent_transfers.end()) return true;
        }
        // 服务端超时没有实际0027可保存。已关闭的银行允许格式正确的迟到选择，
        // 但action总是先处理当前银行，不能吞掉同回合下一次银行的正常交易。
        if(request.size()>=2 && read_le(request.first(2))==0x27) {
            const auto choice=decode_richonline_game_bank_request(request);
            if(std::ranges::find(retired_banks,std::pair{sender,choice.calendar_counter})!=retired_banks.end()) return true;
        }
        return std::any_of(retired.begin(),retired.end(),[&](const auto& entry) {
            return entry.actor==sender && std::ranges::equal(entry.request,request);
        });
    }
    void healthy() const {
        if(phase==Phase::closed) throw CodecError("richonline_classic_session_closed");
    }
    std::vector<Bytes> begin_turn() {
        if(!active[actor] || !active[round_anchor]) throw CodecError("richonline_classic_turn_inactive");
        if(sequence==std::numeric_limits<std::uint64_t>::max())
            throw CodecError("richonline_classic_turn_sequence_overflow");
        // 每条非重播4010加一次日历WORD；轮数只在完整绕回显式起始槽后加一。
        auto packet=encode_richonline_turn4010({board.game_server_id,static_cast<std::int8_t>(actor),
            static_cast<std::int8_t>(round_anchor),0},rules.opaque_turn7);
        // 4010只执行轮首更新；420F(-1)排608A阶段4，才进入掷骰或停走分支。
        std::vector<Bytes> messages{std::move(packet),encode_richonline_empty_turn420f(board.game_server_id)};
        if(statuses[actor].stay && movement_sequence==std::numeric_limits<std::uint64_t>::max())
            throw CodecError("richonline_classic_movement_sequence_overflow");
        ++sequence;calendar=static_cast<std::uint16_t>(calendar+1U);
        static_cast<void>(raw->apply_verified_actor_timer_phase(actor,sequence));
        richonline_status_begin_active_turn(statuses[actor]);
        phase=Phase::roll;pending_opcode.reset();
        if(statuses[actor].stay) {
            // 客户端不掷骰、不发4011；每个连接直接回报0011和当前原位置。
            route={};route_cursor=0;phase=Phase::stationary;
            movement=RichonlineSharedMovementWait{++movement_sequence,calendar,
                board.participants[actor].position,actor,0x11};
        }
        if(rules.log) rules.log("richonline_classic_turn actor="+std::to_string(actor)+
            " sequence="+std::to_string(sequence)+" calendar="+std::to_string(calendar));
        return messages;
    }
    std::vector<Bytes> opening() {
        if(phase!=Phase::loading) throw CodecError("richonline_classic_opening_repeated");
        auto messages=opening_hands.synchronization;
        // 全员收齐4200及每槽4201后，共享宿主才调用stock_action；只发送一次历史。
        messages.insert(messages.end(),stock_opening.begin(),stock_opening.end());
        append(messages,begin_turn());
        for(std::size_t slot=0;slot<world.cards.size();++slot)
            world.cards[slot]->commit_inventory(opening_hands.inventories[slot]);
        return messages;
    }
    std::vector<Bytes> advance(std::vector<Bytes> messages) {
        auto next=actor;
        for(std::size_t step=0;step<active.size();++step) {
            next=static_cast<std::uint8_t>((next+1U)%active.size());
            if(active[next]) break;
        }
        if(!active[next] || std::ranges::count(active,std::uint8_t{1})<2)
            throw CodecError("richonline_classic_last_survivor_settlement_unimplemented");
        // 月数在客户端转为BYTE天数；结算业务尚未装配时明确停在边界，不无限续局。
        const auto limit=static_cast<std::uint8_t>(startup.game_months*30U);
        if(next==round_anchor && limit && completed_rounds+2>limit)
            throw CodecError("richonline_classic_month_settlement_unimplemented");
        richonline_status_finish_previous_turn(statuses[actor]);
        actor=next;
        if(actor==round_anchor) ++completed_rounds;
        append(messages,begin_turn());return messages;
    }
    std::vector<Bytes> complete(std::vector<Bytes> messages) {
        if(!collision_pending) throw CodecError("richonline_classic_phase6_not_pending");
        const auto before=collision_actors();
        const auto plan=plan_richonline_collision(actor,0,false,before,*rules.card_resources,startup.map_name,rules.script);
        // 先准备/验证全部角色的变化和Lua意图，再统一提交。4013已让客户端执行
        // 本地6061，不能为同一转移再造一个网络扣卡包；满手也遵循原生插入/合成规则。
        if(collision_actors()!=plan.before) throw CodecError("richonline_classic_collision_stale");
        const auto& person=board.participants[actor];
        const bool direction=plan.evaluate_junction && statuses[actor].possession!=7 && !statuses[actor].sleepwalking &&
            junction.begin(startup.topology,{person.position,person.direction,calendar},rules.now());
        for(std::size_t slot=0;slot<world.cards.size();++slot) world.cards[slot]->commit_inventory(plan.after[slot].inventory);
        collision_pending=false;
        if(rules.log) rules.log("richonline_classic_phase6 actor="+std::to_string(actor)+
            " sequence="+std::to_string(sequence)+" transfers="+std::to_string(plan.transfers.size()));
        if(direction) {
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
            *result.pending_opcode==0x27 || *result.pending_opcode==0x28 || *result.pending_opcode==0x34 ||
            *result.pending_opcode==0x76))
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
    std::vector<bool> rent_transfer_targets() const {
        std::vector<bool> eligible(board.participants.size(),false);
        for(std::uint8_t slot=0;slot<board.participants.size();++slot) {
            const auto& state=raw->actor(slot);
            if(!state.hotel1493 || !state.hospital1494 || !state.jail1495 || !state.kidnapped1497)
                throw CodecError("richonline_classic_rent_transfer_target_unknown");
            // 7174B0与7BC100都只排除原付款者及四种原始状态；不额外排除地主、
            // 冻结或梦游，不重用普通租金的“地主暂停收租”资格判断。
            eligible[slot]=slot!=actor && active[slot] && !disconnected[slot] && *state.hotel1493==-1 &&
                *state.hospital1494==-1 && *state.jail1495==-1 && *state.kidnapped1497==-1;
        }
        return eligible;
    }
    std::vector<Bytes> begin_rent_transfer(const RichonlineClassicPropertyState& property,std::uint32_t amount,
        const RichonlineChanceInventory& inventory,const RichonlineGameFundsSnapshot& payer,
        const RichonlineGameFundsSnapshot& payee) {
        if(rent_transfer || !property.owner) throw CodecError("richonline_classic_rent_transfer_already_pending");
        std::int8_t card_slot=-1;
        for(std::size_t index=0;index<inventory.size();++index) if(inventory[index].card_id==1056) {
            if(inventory[index].count<=0) throw CodecError("richonline_classic_rent_transfer_card_invalid");
            card_slot=static_cast<std::int8_t>(index);break;
        }
        if(card_slot<0) throw CodecError("richonline_classic_rent_transfer_card_missing");
        RichonlineRentTransferState state{board.game_server_id,calendar,actor,*property.owner,amount,{},
            rent_transfer_targets(),inventory,card_slot};
        for(std::uint8_t slot=0;slot<board.participants.size();++slot) state.funds.push_back(world.ledger->snapshot(slot));
        if(state.funds[actor]!=payer || state.funds[*property.owner]!=payee ||
            world.cards[actor]->inventory()!=inventory || world.property->snapshot(property.id)!=property)
            throw CodecError("richonline_classic_rent_transfer_entry_stale");
        auto messages=std::vector<Bytes>{stop()};
        rent_transfer=PendingRentTransfer{std::move(state),property,board.participants[actor].position,sequence,
            rules.now()+rules.decision_timeout};
        phase=Phase::rent_transfer;pending_opcode=0x76;
        // 4013使所有客户端保存同一type0金额并排608C，只有原付款人打开UI27。
        // 此时不扣嫁祸卡、不改资金，也不提前执行地产附加效果或phase6。
        return messages;
    }
    std::vector<Bytes> finish_rent_transfer(const RichonlineRentTransferChoice& choice,bool timed_out) {
        if(!rent_transfer || phase!=Phase::rent_transfer) throw CodecError("richonline_classic_rent_transfer_not_pending");
        const auto& pending=*rent_transfer;
        if(pending.state.original_payer!=actor || pending.state.calendar!=calendar || pending.sequence!=sequence ||
            pending.position!=board.participants[actor].position ||
            world.property->snapshot(pending.property.id)!=pending.property ||
            world.cards[actor]->inventory()!=pending.state.inventory || pending.state.eligible!=rent_transfer_targets())
            throw CodecError("richonline_classic_rent_transfer_pending_stale");
        for(std::uint8_t slot=0;slot<board.participants.size();++slot)
            if(world.ledger->snapshot(slot)!=pending.state.funds[slot])
                throw CodecError("richonline_classic_rent_transfer_funds_stale");
        auto plan=plan_richonline_rent_transfer(pending.state,choice,timed_out,rules.script);
        auto messages=std::vector<Bytes>{std::move(plan.response)};
        std::optional<PreparedRetirement> retirement;
        if(plan.bankrupt) {
            retirement=prepare_bankruptcy(plan.payer);
            if(std::ranges::count(active,std::uint8_t{1})>2)
                messages.push_back(richonline_eliminate_actor(board.game_server_id,static_cast<std::int8_t>(plan.payer)));
        }
        retired_rent_transfers.emplace_back(actor,calendar);
        if(retired_rent_transfers.size()>64) retired_rent_transfers.pop_front();
        if(!world.ledger->commit_sequence(plan.funds,[&]() {
            if(world.cards[actor]->inventory()!=pending.state.inventory ||
                world.property->snapshot(pending.property.id)!=pending.property) return false;
            if(retirement && !commit_retirement(*retirement)) return false;
            if(retirement) retire_actor(plan.payer);
            world.cards[actor]->commit_inventory(plan.inventory);return true;
        })) throw CodecError("richonline_classic_rent_transfer_commit_stale");
        rent_transfer.reset();pending_opcode.reset();
        if(retirement && std::ranges::count(active,std::uint8_t{1})==1)
            return finish_last_survivor(std::move(messages),plan.payer);
        if(rules.log) rules.log("richonline_classic_rent_transfer actor="+std::to_string(actor)+
            " payer="+std::to_string(plan.payer)+" charged="+std::to_string(plan.charged)+
            " target="+std::to_string(plan.target)+" timed_out="+std::to_string(timed_out)+
            " sequence="+std::to_string(sequence));
        // 40C6(type0)排6080(2,5)，只进入附加效果，不再调用租金入口或补第二条4013。
        if(!active[actor]) {collision_pending=false;return advance(std::move(messages));}
        return property_effects(std::move(messages));
    }
    PreparedRetirement prepare_bankruptcy(std::uint8_t bankrupt) const {
        if(bankrupt>=active.size() || !active[bankrupt])
            throw CodecError("richonline_classic_bankruptcy_actor_invalid");
        const auto count=std::ranges::count(active,std::uint8_t{1});
        if(count<2)throw CodecError("richonline_classic_bankruptcy_roster_invalid");
        // 只有显式绑定全员持久结算和奖励策略才允许最后一人退场。
        if(count==2 && !terminal)
            throw CodecError("richonline_classic_last_survivor_settlement_unimplemented");
        auto after=active;after[bankrupt]=0;
        if(count==2)terminal->validate_last_survivor(after);
        auto anchor=round_anchor;
        if(anchor==bankrupt) {
            do {anchor=static_cast<std::uint8_t>((anchor+1U)%after.size());} while(!after[anchor]);
        }
        auto next=actor;
        do {next=static_cast<std::uint8_t>((next+1U)%after.size());} while(!after[next]);
        const auto limit=static_cast<std::uint8_t>(startup.game_months*30U);
        if(count>2 && next==anchor && limit && completed_rounds+2>limit)
            throw CodecError("richonline_classic_month_settlement_unimplemented");
        if(rules.script) {
            const auto result=rules.script->call("game.classic_retirement",{{"active",active},{"bankrupt",bankrupt},
                {"actor",actor},{"anchor",round_anchor}});
            const LuaValue expected{{"active",after},{"anchor",anchor},{"next",next}};
            if(result!=expected || !result.at("anchor").is_number_integer() || !result.at("next").is_number_integer())
                throw CodecError("lua_classic_retirement_invalid");
        }
        return {world.property->prepare_retirement(bankrupt),world.stocks ?
            std::optional{world.stocks->prepare_retirement(bankrupt)} : std::nullopt};
    }
    bool commit_retirement(const PreparedRetirement& plan) noexcept {
        // 先核对全部参与者，再执行无分配写入；不能先回收地产再发现股票计划过期。
        if(!world.property->matches(plan.property) ||
            (plan.stocks && (!world.stocks || !world.stocks->matches(*plan.stocks)))) return false;
        if(!world.property->commit_retirement(plan.property)) std::terminate();
        if(plan.stocks && !world.stocks->commit(*plan.stocks)) std::terminate();
        return true;
    }
    std::vector<Bytes> finish_last_survivor(std::vector<Bytes> messages,std::uint8_t bankrupt) {
        if(!terminal)throw CodecError("richonline_classic_terminal_missing");
        phase=Phase::settling;collision_pending=false;movement.reset();pending_opcode.reset();
        // 末笔支出已进入权威账本；全员奖励和战绩原子入库后才发最后400E、胜利及战绩表。
        // 任一失败由共享层关闭业务，不重跑租金、不伪造换人，也不盲目重发动画。
        append(messages,terminal->finish(active,bankrupt));return messages;
    }
    void retire_actor(std::uint8_t bankrupt) noexcept {
        active[bankrupt]=0;
        // 明确的服务端轮序政策：先手淘汰时改为其后的首个存活槽，并通过4010+5
        // 同步；日历与租金周期只按这个真实锚点推进，不把已经淘汰的槽继续当先手。
        if(round_anchor==bankrupt) {
            do {round_anchor=static_cast<std::uint8_t>((round_anchor+1U)%active.size());} while(!active[round_anchor]);
        }
        // 7BE160不清手牌和票券。股票已在同一提交回调内回收，不按卖出给破产者存款。
        // 当前会话尚无关系卡和建筑增益写入口。
        // 7F9560仅清已实现的移动状态；原始住院/监狱等字段不借破产擅自重置。
        auto& state=statuses[bankrupt];
        state.one_step=state.six_steps=state.turtle=state.stay=state.sleepwalking=state.frozen=0;
    }
    std::vector<Bytes> rent(const RichonlineClassicPropertyState& property) {
        if(!property.owner || *property.owner>=statuses.size() || *property.owner==actor)
            throw CodecError("richonline_classic_rent_owner_invalid");
        const auto owner=*property.owner;
        const auto& owner_raw=raw->actor(owner);
        const auto& owner_status=statuses[owner];
        if(!owner_raw.hotel1493 || !owner_raw.hospital1494 || !owner_raw.jail1495 ||
            !owner_raw.kidnapped1497 || !owner_status.possession || !statuses[actor].possession)
            throw CodecError("richonline_classic_rent_state_unknown");
        // 7C94xx读取地主的状态，而1472/1480关系由付款者按地主索引读取。
        // 本会话尚未开放关系卡和地产封闭/加倍写入口，沿用7F3840/地图初始化的零值；
        // 以后接这些写入口时，必须一起扩展本处权威状态，不能只让客户端改变关系。
        const bool suppressed=owner_status.possession==7 || owner_status.sleepwalking || owner_status.frozen ||
            *owner_raw.hotel1493!=-1 || *owner_raw.hospital1494!=-1 ||
            *owner_raw.jail1495!=-1 || *owner_raw.kidnapped1497!=-1;
        const auto possession=*statuses[actor].possession;
        const auto initial_scale=startup.recipients.front().snapshot.monetary_scale;
        // 当前会话只从新局4004开始：首次先手回合不增日，此后每完整轮增日一次。
        // 正基准每30次增日加1；类型19和外部4004改系数尚无写入口。
        const auto scale=static_cast<std::uint64_t>(initial_scale)+(initial_scale ? completed_rounds/30U : 0U);
        if(scale>static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max()))
            throw CodecError("richonline_classic_rent_scale_unsupported");
        const auto quote=suppressed || possession==0 ? 0 :
            world.property->rent_quote(property.id,static_cast<std::uint32_t>(scale));
        auto amount=possession==1 ? std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(quote)*2U) : quote;
        if(amount<0) throw CodecError("richonline_classic_rent_negative_unsupported");
        const auto payer=world.ledger->snapshot(actor),payee=world.ledger->snapshot(owner);
        if(!payer.funds.deposit || !payee.funds.deposit ||
            static_cast<std::uint64_t>(payer.funds.cash)+*payer.funds.deposit>
                static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max()))
            throw CodecError("richonline_classic_rent_balance_unsupported");
        const auto inventory=world.cards[actor]->inventory();
        const bool free_eligible=rules.card_resources->automatic_card_eligible(startup.map_name,1050);
        const bool transfer_eligible=rules.card_resources->automatic_card_eligible(startup.map_name,1056);
        std::optional<RichonlinePlayerCards::PreparedConsumption> free_card;
        const char* outcome="paid";
        if(suppressed || possession==0) {amount=0;outcome="waived";}
        else {
            if(amount>=5000 && free_eligible) {
                for(std::size_t index=0;index<inventory.size();++index) if(inventory[index].card_id==1050) {
                    free_card=world.cards[actor]->prepare_consumption(static_cast<std::int8_t>(index),1050);
                    if(!free_card) throw CodecError("richonline_classic_rent_card_invalid");
                    outcome="free_card";break;
                }
            }
            if(!free_card && ((amount>=5000 && free_eligible) || (amount>=10000 && transfer_eligible)) &&
                (!rules.secondary_rent_cards_absent || !rules.secondary_rent_cards_absent(actor)))
                throw CodecError("richonline_classic_rent_secondary_cards_unknown");
            if(!free_card && amount>=10000 && transfer_eligible && std::ranges::any_of(inventory,
                [](const auto& card){return card.card_id==1056;})) outcome="transfer_pending";
            if(std::string_view(outcome)=="paid" && static_cast<std::uint32_t>(amount)>=
                payer.funds.cash+*payer.funds.deposit) outcome="bankrupt";
        }
        if(rules.script) {
            auto cards=LuaValue::array();
            for(const auto& card:inventory) cards.push_back({{"card",card.card_id},{"count",card.count}});
            const auto plan=rules.script->call("property.classic_rent_payment",{{"quote",quote},
                {"possession",possession},{"suppressed",suppressed},{"cash",payer.funds.cash},
                {"deposit",*payer.funds.deposit},{"inventory",std::move(cards)},
                {"free_eligible",free_eligible},{"transfer_eligible",transfer_eligible}});
            const LuaValue expected{{"amount",amount},{"free_slot",free_card ? static_cast<int>(free_card->slot) : -1},
                {"outcome",outcome}};
            if(plan!=expected || !plan.at("amount").is_number_integer() || !plan.at("free_slot").is_number_integer())
                throw CodecError("lua_classic_rent_payment_invalid");
        }
        // 先识别等待/破产再提交，未实现的后继不得吞卡、扣光余额后伪造4010。
        if(std::string_view(outcome)=="transfer_pending")
            return begin_rent_transfer(property,static_cast<std::uint32_t>(amount),inventory,payer,payee);
        const bool bankrupt=std::string_view(outcome)=="bankrupt";
        std::optional<PreparedRetirement> retirement;
        if(bankrupt) retirement=prepare_bankruptcy(actor);
        const auto charged=bankrupt ? payer.funds.cash+*payer.funds.deposit :
            std::string_view(outcome)=="paid" ? static_cast<std::uint32_t>(amount) : 0U;
        auto payer_after=payer.funds,payee_after=payee.funds;
        if(charged>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max())-*payee_after.deposit)
            throw CodecError("richonline_classic_rent_recipient_overflow");
        const auto cash_paid=std::min(charged,payer_after.cash);
        payer_after.cash-=cash_paid;*payer_after.deposit-=charged-cash_paid;*payee_after.deposit+=charged;
        auto messages=std::vector<Bytes>{stop()};
        if(bankrupt && std::ranges::count(active,std::uint8_t{1})>2)
            messages.push_back(richonline_eliminate_actor(board.game_server_id,static_cast<std::int8_t>(actor)));
        const std::array updates{RichonlineGameFundsUpdate{actor,payer,payer_after},
            RichonlineGameFundsUpdate{owner,payee,payee_after}};
        if(!world.ledger->commit_batch(updates,[&]() {
            if(world.cards[actor]->inventory()!=inventory || world.property->snapshot(property.id)!=property) return false;
            if(retirement && !commit_retirement(*retirement)) return false;
            if(retirement) retire_actor(actor);
            if(free_card) world.cards[actor]->commit_inventory(free_card->remaining_inventory);
            return true;
        })) throw CodecError("richonline_classic_rent_commit_stale");
        if(bankrupt && std::ranges::count(active,std::uint8_t{1})==1)
            return finish_last_survivor(std::move(messages),actor);
        // 4013已触发客户端6060/6061；只镜像账本/手牌，不发第二笔扣款或扣卡包。
        if(rules.log) rules.log("richonline_classic_rent actor="+std::to_string(actor)+
            " owner="+std::to_string(owner)+" property="+std::to_string(property.id)+
            " sequence="+std::to_string(sequence)+" charged="+std::to_string(charged)+" outcome="+outcome);
        if(bankrupt) {collision_pending=false;return advance(std::move(messages));}
        return property_effects(std::move(messages));
    }
    std::vector<RichonlineClassicRainActor> rain_actors() const {
        std::vector<RichonlineClassicRainActor> result;
        result.reserve(active.size());
        for(std::uint8_t slot=0;slot<active.size();++slot)
            result.push_back({active[slot]!=0,raw->actor(slot),statuses[slot]});
        return result;
    }
    std::vector<Bytes> money_news(const RichonlineClassicTurnContext& current) {
        if(!rules.news || current.landing.property_ref!=-1)
            throw CodecError("richonline_classic_news_authority_missing");
        if(richonline_landing_controlled(statuses[actor])) return complete({stop()});
        const auto fines_before=news_fines;
        const auto active_before=active;
        std::vector<RichonlineGameFundsSnapshot> all_funds;
        for(std::uint8_t slot=0;slot<active.size();++slot) all_funds.push_back(world.ledger->snapshot(slot));
        const auto& before=all_funds[actor];
        const auto inventory_before=world.cards[actor]->inventory();
        const auto rain_before=rain_actors();
        const auto event=rules.news->select(current,before,fines_before);
        if(event.opcode>=0x408b && event.opcode<=0x408f) {
            if(!event.property) throw CodecError("richonline_classic_news_property_missing");
            const auto plan=world.property->prepare_disaster(*event.property,event.opcode==0x408b ? 1 : 5);
            auto messages=prepare_richonline_classic_disaster_news(board.game_server_id,current.landing,
                event,plan,rules.script);
            const auto detail="richonline_classic_property_news actor="+std::to_string(actor)+
                " sequence="+std::to_string(sequence)+" opcode="+std::to_string(event.opcode)+
                " property="+std::to_string(plan.before().id)+
                " level_before="+std::to_string(plan.before().level)+" level_after="+std::to_string(plan.after().level)+
                " kind_before="+std::to_string(plan.before().kind)+" kind_after="+std::to_string(plan.after().kind);
            if(active!=active_before || statuses[actor]!=current.landing.actor_status ||
                board.participants[actor].position!=current.landing.position ||
                !world.property->commit_disaster(plan))
                throw CodecError("richonline_classic_news_commit_stale");
            if(rules.log) rules.log(detail);
            // 动画在客户端队列中先降级再stage2；仅广播事件，不再补发一次降级包。
            return complete(std::move(messages));
        }
        if(event.property) throw CodecError("richonline_classic_news_parameters_invalid");
        if(event.opcode==0x4072) {
            if(event.amount!=0 || event.picture) throw CodecError("richonline_classic_news_parameters_invalid");
            if(!rules.motion_cards) throw CodecError("richonline_classic_rain_rules_missing");
            auto plan=prepare_richonline_classic_rain_news(board.game_server_id,current.landing,
                rain_before,*rules.motion_cards,rules.script);
            // 全部准备完成才写入；同一共享对局锁下复核每人的原始状态和计时器。
            if(rain_actors()!=plan.before || board.participants[actor].position!=current.landing.position)
                throw CodecError("richonline_classic_news_commit_stale");
            for(std::size_t slot=0;slot<statuses.size();++slot) statuses[slot].stay=plan.after[slot].status.stay;
            return complete(std::move(plan.messages));
        }
        if(event.opcode==0x4078) {
            if(event.amount!=0 || event.picture) throw CodecError("richonline_classic_news_parameters_invalid");
            auto plan=prepare_richonline_classic_card_sale_news(board.game_server_id,current.landing,before,
                inventory_before,*rules.resale,rules.script);
            const auto detail="richonline_classic_card_sale_news actor="+std::to_string(actor)+
                " sequence="+std::to_string(sequence)+" tickets="+std::to_string(plan.tickets_received);
            const std::array updates{plan.funds};
            if(!world.ledger->commit_batch(updates,[&]() noexcept {
                if(active!=active_before || news_fines!=fines_before ||
                    statuses[actor]!=current.landing.actor_status ||
                    board.participants[actor].position!=current.landing.position ||
                    world.cards[actor]->inventory()!=plan.inventory_before) return false;
                world.cards[actor]->commit_inventory(plan.inventory_after);return true;
            })) throw CodecError("richonline_classic_news_commit_stale");
            if(rules.log) rules.log(detail);
            // 4078自己清手牌并加点券；不再发逐槽4032或另一个点券增量包。
            return complete(std::move(plan.messages));
        }
        if(event.opcode==0x406f) {
            auto plan=prepare_richonline_classic_savings_news(board.game_server_id,current.landing,event,
                all_funds,active_before,rules.script);
            auto detail="richonline_classic_savings_news actor="+std::to_string(actor)+
                " sequence="+std::to_string(sequence)+" amount="+std::to_string(event.amount);
            for(const auto recipient:plan.recipients) detail+=" recipient="+std::to_string(recipient);
            if(!world.ledger->commit_batch(plan.funds,[&]() {
                return active==active_before && news_fines==fines_before &&
                    statuses[actor]==current.landing.actor_status &&
                    board.participants[actor].position==current.landing.position;
            })) throw CodecError("richonline_classic_news_commit_stale");
            if(rules.log) rules.log(detail);
            // 406F只广播一次；每个客户端自行计算并列名单，最后排一次stage2。
            return complete(std::move(plan.messages));
        }
        auto plan=prepare_richonline_classic_money_news(board.game_server_id,current.landing,event,before,
            fines_before,rules.script);
        if(statuses[actor]!=current.landing.actor_status || board.participants[actor].position!=current.landing.position)
            throw CodecError("richonline_classic_news_context_stale");
        std::optional<PreparedRetirement> retirement;
        if(plan.bankrupt) retirement=prepare_bankruptcy(actor);
        if(plan.bankrupt && std::ranges::count(active,std::uint8_t{1})>2)
            plan.messages.push_back(richonline_eliminate_actor(board.game_server_id,static_cast<std::int8_t>(actor)));
        const auto diagnostic="richonline_classic_news actor="+std::to_string(actor)+
            " sequence="+std::to_string(sequence)+" opcode="+std::to_string(event.opcode)+
            " amount="+std::to_string(event.amount)+" cash="+std::to_string(plan.funds.after.cash)+
            " deposit="+std::to_string(*plan.funds.after.deposit)+" fines="+std::to_string(plan.fines_after)+
            " bankrupt="+std::to_string(plan.bankrupt);
        const std::array updates{plan.funds};
        if(!world.ledger->commit_batch(updates,[&]() {
            if(news_fines!=plan.fines_before || statuses[actor]!=current.landing.actor_status ||
                board.participants[actor].position!=current.landing.position) return false;
            if(retirement && !commit_retirement(*retirement)) return false;
            if(retirement) retire_actor(actor);
            news_fines=plan.fines_after;return true;
        })) throw CodecError("richonline_classic_news_commit_stale");
        if(rules.log) rules.log(diagnostic);
        if(plan.bankrupt) {
            if(std::ranges::count(active,std::uint8_t{1})==1)
                return finish_last_survivor(std::move(plan.messages),actor);
            collision_pending=false;return advance(std::move(plan.messages));
        }
        // 客户端金额新闻已排stage2；无地产引用时再由统一phase6和岔路收尾。
        return complete(std::move(plan.messages));
    }
    std::optional<RichonlinePortalLandingPlan> portal_plan(const RichonlineLandingContext& landing) const {
        const auto scripted=raw->game().scripted_event83830;
        if(!scripted) throw CodecError("richonline_classic_portal_game_unknown");
        if(landing.static_type==58)
            return plan_richonline_random_teleport_landing(board.game_server_id,startup.topology,landing,*scripted!=-1);
        if(landing.static_type==28 || landing.static_type==61)
            return plan_richonline_portal_landing(board.game_server_id,startup.topology,
                startup.topology.landing_portal_pair(landing.static_type),landing,*scripted!=-1);
        return {};
    }
    std::optional<std::vector<Bytes>> portal_landing(const RichonlineLandingContext& landing) {
        const auto plan=portal_plan(landing);
        if(!plan) return {};
        const bool skip=plan->continuation==RichonlinePortalContinuation::property_phase2;
        // 受控/脚本跳过传送时，有地产仍进入原phase2；本会话尚未开放这些状态写入口。
        if(skip && landing.property_ref>=0) return {};
        std::optional<std::size_t> chosen;
        if(plan->continuation==RichonlinePortalContinuation::random_teleport) {
            if(plan->random_destinations.empty()) throw CodecError("richonline_classic_portal_candidates_missing");
            chosen=rules.random(plan->random_destinations.size());
        }
        auto prepared=prepare_richonline_portal_messages(board.game_server_id,startup.map_name,*plan,chosen,rules.script);
        const auto current=portal_plan(context().landing);
        if(!current || statuses[actor]!=plan->expected.actor_status ||
            board.participants[actor].position!=plan->expected.position ||
            current->continuation!=plan->continuation || current->authoritative_position!=plan->authoritative_position ||
            current->confirmation!=plan->confirmation || current->random_destinations!=plan->random_destinations)
            throw CodecError("richonline_classic_portal_plan_stale");
        if(skip) return complete(std::move(prepared.messages));
        const auto destination=prepared.destination;
        if(!startup.topology.cell(destination).walkable || destination==landing.position ||
            (landing.static_type==61 && startup.topology.portal_destination(landing.position)!=destination))
            throw CodecError("richonline_classic_portal_destination_invalid");
        // 7C54B0/67C080只重定位并等待服务器，没有出口phase2、phase6或岔路应答。
        // 地面物和宠物还未装配到经典会话；以后接入时需单独处理出口地雷与宠物位置。
        board.participants[actor].position=destination;
        collision_pending=false;
        if(rules.log) rules.log("richonline_classic_portal actor="+std::to_string(actor)+
            " source="+std::to_string(landing.position)+" destination="+std::to_string(destination)+
            " sequence="+std::to_string(sequence)+(chosen ? " policy=native-uniform-walkable-road-v1" : " policy=emp-pair"));
        return advance(std::move(prepared.messages));
    }
    std::vector<Bytes> land() {
        if(collision_pending) throw CodecError("richonline_classic_phase6_already_pending");
        static_cast<void>(collision_actors());
        collision_pending=true;
        const auto current=context();
        if(auto messages=portal_landing(current.landing)) return std::move(*messages);
        // 先完成静态/地产业务，同格效果由complete统一在phase6执行，不能提前抢卡。
        if(auto result=services.landing(current)) return accept_result(std::move(*result));
        if(current.landing.static_type==1 && rules.news) return money_news(current);
        if(current.landing.static_type==9) {
            if(current.landing.property_ref!=-1)
                throw CodecError("richonline_classic_bank_property_unimplemented");
            auto messages=std::vector<Bytes>{stop()};
            append(messages,open_bank(RichonlineGameBankVisit::landing));return messages;
        }
        if(current.landing.property_ref>=0) {
            const auto property=world.property->snapshot(current.landing.property_ref);
            if(property.kind!=0 && property.kind!=1)
                throw CodecError("richonline_classic_property_landing_unimplemented");
            if(property.owner && *property.owner!=actor)
                return rent(property);
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
        auto proposed=build_richonline_route(startup.topology,
            {person.position,person.direction,budget,{},true,static_cast<bool>(bank)},rules.random);
        // 最后一步仍停在入口，等0011全员汇合才传送；途中61由不可变路线处理。
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
        raw->apply_s2c4011_movement(actor);
        route_cursor=0;wait_for_segment();
        phase=Phase::moving;
    }
    std::optional<std::size_t> next_bank() const {
        // 最后一格使用0011和落点4013，只有尚未走完的中间格使用0028。
        if(!bank) return {};
        for(auto index=route_cursor;index+1<route.landings.size();++index)
            if(startup.topology.cell(route.landings[index]).static_type==9) return index;
        return {};
    }
    void wait_for_segment() {
        if(route.landings.empty() || route_cursor>=route.landings.size() ||
            movement_sequence==std::numeric_limits<std::uint64_t>::max())
            throw CodecError("richonline_classic_movement_segment_invalid");
        const auto checkpoint=next_bank();
        const auto endpoint=route.landings[checkpoint.value_or(route.landings.size()-1)];
        movement=RichonlineSharedMovementWait{++movement_sequence,calendar,endpoint,actor,
            static_cast<std::uint16_t>(checkpoint ? 0x28 : 0x11)};
    }
    std::vector<Bytes> open_bank(RichonlineGameBankVisit visit,std::optional<std::size_t> checkpoint={}) {
        if(!bank || bank_funds || bank_checkpoint || bank->active())
            throw CodecError("richonline_classic_bank_unavailable");
        const auto funds=world.ledger->snapshot(actor);
        if(!funds.funds.deposit) throw CodecError("richonline_classic_bank_deposit_unknown");
        auto result=bank->begin({actor,board.participants[actor].position,calendar,visit,
            {funds.funds.cash,*funds.funds.deposit},false});
        bank_funds=funds;bank_checkpoint=checkpoint;phase=Phase::bank;pending_opcode=0x27;
        return bank_result(std::move(result));
    }
    std::vector<Bytes> bank_result(RichonlineGameBankResult result) {
        if(!bank_funds || result.entry.actor_slot!=actor || result.entry.calendar_counter!=calendar ||
            result.entry.position!=board.participants[actor].position ||
            result.entry.balance.cash!=bank_funds->funds.cash || result.entry.balance.deposit!=bank_funds->funds.deposit ||
            world.ledger->snapshot(actor)!=*bank_funds)
            throw CodecError("richonline_classic_bank_snapshot_stale");
        if(result.continuation==RichonlineGameBankContinuation::await_choice) return std::move(result.messages);
        const bool passing=result.entry.visit==RichonlineGameBankVisit::passing;
        if(passing!=bank_checkpoint.has_value() || (passing &&
            (result.continuation!=RichonlineGameBankContinuation::resume_movement ||
             *bank_checkpoint+1>=route.landings.size())) || (!passing &&
            result.continuation!=RichonlineGameBankContinuation::continue_landing))
            throw CodecError("richonline_classic_bank_continuation_invalid");
        auto after=bank_funds->funds;after.cash=result.after.cash;after.deposit=result.after.deposit;
        retired_banks.emplace_back(actor,calendar);
        if(retired_banks.size()>64) retired_banks.pop_front();
        world.ledger->commit(actor,*bank_funds,after);
        bank_funds.reset();pending_opcode.reset();
        if(rules.log) rules.log("richonline_classic_bank_completed actor="+std::to_string(actor)+
            " calendar="+std::to_string(calendar)+" position="+std::to_string(result.entry.position)+
            " cash="+std::to_string(after.cash)+" deposit="+std::to_string(*after.deposit)+
            " passing="+std::to_string(passing));
        if(passing) {
            route_cursor=*bank_checkpoint+1;bank_checkpoint.reset();
            // 402A已让每个客户端恢复缓存的4011，并自增路线游标。这里只换下一等待，
            // 不重发4011、不重掷骰、不提前提交终点，也不重复扣指定骰点卡。
            wait_for_segment();phase=Phase::moving;return std::move(result.messages);
        }
        return complete(std::move(result.messages));
    }
    std::vector<Bytes> stock_action(std::uint8_t sender,const RichonlineStockRequest& request) {
        healthy();
        if(!world.stocks || sender>=active.size() || phase==Phase::loading)
            throw CodecError("richonline_classic_stock_context_invalid");
        // 股票窗口不依赖走子者，没有日历/请求序号；相同买卖可连续成交，不能去重。
        // 已淘汰或结算中的迟到交易不触发移动、不发4206、不改变已冻结的结算资产。
        if(!active[sender] || phase==Phase::settling) {
            if(rules.log) rules.log("richonline_classic_stock_refused actor="+std::to_string(sender)+" reason=inactive_or_settling");
            return {};
        }
        const auto before=world.ledger->snapshot(sender);
        const bool waiting_bank=phase==Phase::bank && actor==sender;
        if(waiting_bank && (!bank_funds || *bank_funds!=before || !before.funds.deposit ||
            !bank->matches_balance(sender,{before.funds.cash,*before.funds.deposit})))
            throw CodecError("richonline_classic_stock_bank_stale");
        if(rent_transfer && rent_transfer->state.funds[sender]!=before)
            throw CodecError("richonline_classic_stock_rent_stale");
        const auto trade=world.stocks->prepare(sender,request);
        if(!trade.accepted()) {
            if(rules.log) rules.log("richonline_classic_stock_refused actor="+std::to_string(sender)+" reason="+trade.reason());
            return {};
        }
        std::vector<Bytes> messages{trade.response()};
        if(!world.stocks->commit(trade)) throw CodecError("richonline_classic_stock_commit_stale");
        const auto after=world.ledger->snapshot(sender);
        // 只承认这笔已提交的成交导致的余额变化；未知写入仍按旧快照冲突拒绝。
        // 保留银行期限、租金金额与选择资格，不重新打开窗口，也不重算已同步的租金。
        if(waiting_bank) {
            if(!bank->synchronize_balance(sender,{before.funds.cash,*before.funds.deposit},
                {after.funds.cash,*after.funds.deposit})) std::terminate();
            bank_funds=after;
        }
        if(rent_transfer) rent_transfer->state.funds[sender]=after;
        if(rules.log) rules.log("richonline_classic_stock_trade actor="+std::to_string(sender)+
            " slot="+std::to_string(request.slot)+" quantity="+std::to_string(request.quantity)+
            " buy="+std::to_string(request.action==RichonlineStockAction::buy)+
            " deposit_before="+std::to_string(*before.funds.deposit)+" deposit_after="+std::to_string(*after.funds.deposit));
        return messages;
    }
    std::vector<Bytes> stock_card(View request) {
        const auto opcode=read_le(request.first(2));
        // use只由已认证的当前行动者在roll阶段进入；与无日历的0200/0201分开。
        std::vector<Bytes> refused{encode_richonline_dice_recovery400b(board.game_server_id)};
        const auto reject=[&](const std::string& reason) {
            if(rules.log) rules.log("richonline_classic_stock_card_refused actor="+std::to_string(actor)+
                " opcode="+std::to_string(opcode)+" reason="+reason);
            return refused;
        };
        if(opcode==0x97) {
            const auto use=decode_richonline_stock_forced_sale_request(request);
            if(!world.stocks) return reject("stock_not_enabled");
            const auto plan=world.stocks->prepare_forced_sale(actor,use,active,*world.cards[actor]);
            if(!plan.accepted()) return reject(plan.reason());
            std::vector<Bytes> messages{plan.response()};
            remember(actor,request);
            if(!world.stocks->commit(plan,active,*world.cards[actor]))
                throw CodecError("richonline_classic_stock_forced_sale_stale");
            if(rules.log) rules.log("richonline_classic_stock_forced_sale actor="+std::to_string(actor)+
                " stock="+std::to_string(use.stock_slot)+" sequence="+std::to_string(sequence));
            return messages;
        }
        const auto use=decode_richonline_stock_subscription_request(request);
        if(!world.stocks) return reject("stock_not_enabled");
        if(use.target>=active.size() || use.target==actor || !active[use.target])
            return reject("target_not_active_opponent");
        if(!world.cards[actor]->prepare_consumption(use.inventory_slot,1123)) return reject("card_not_owned");
        const RichonlineClassicSubscriptionContext snapshot{actor,use.target,use.stock_slot,
            world.stocks->quote(use.stock_slot),world.stocks->holding(actor,use.stock_slot),
            world.stocks->holding(use.target,use.stock_slot),world.ledger->snapshot(actor),world.ledger->snapshot(use.target)};
        std::uint32_t quantity=0;
        if(snapshot.seller_holding.quantity) {
            if(!rules.subscription_quantity) return reject("subscription_quantity_policy_missing");
            quantity=rules.subscription_quantity(snapshot);
        }
        const auto plan=world.stocks->prepare_subscription(actor,use,quantity,active,*world.cards[actor]);
        if(!plan.accepted()) return reject(plan.reason());
        std::vector<Bytes> messages{plan.response()};
        remember(actor,request);
        if(!world.stocks->commit(plan,active,*world.cards[actor]))
            throw CodecError("richonline_classic_stock_subscription_stale");
        if(rules.log) rules.log("richonline_classic_stock_subscription actor="+std::to_string(actor)+
            " target="+std::to_string(use.target)+" stock="+std::to_string(use.stock_slot)+
            " quantity="+std::to_string(quantity)+" consumes_card="+std::to_string(plan.consumes_card())+
            " sequence="+std::to_string(sequence));
        return messages;
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
        if(phase==Phase::settling) {
            if(was_retired(sender,request))return {};
            throw CodecError("richonline_classic_action_after_settlement");
        }
        if(!active[sender]) {
            if(was_retired(sender,request)) return {};
            throw CodecError("richonline_classic_inactive_actor_request");
        }
        if(sender!=actor) throw CodecError("richonline_classic_sender_not_active");
        if(phase==Phase::roll) {
            if(opcode==0x96 || opcode==0x97) return stock_card(request);
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
        if(phase==Phase::stationary && opcode==0x11) {
            const auto stopped=std::get<RichonlineMoveStop11>(parse_richonline_movement_request(request));
            if(!movement || movement->opcode!=0x11 || stopped.endpoint!=movement->endpoint ||
                stopped.endpoint!=board.participants[actor].position)
                throw CodecError("richonline_classic_endpoint_mismatch");
            remember(sender,request);movement.reset();
            // 零步仍按原位置触发落点、同格效果及岔路；不能直接跳到下一角色。
            return land();
        }
        if(phase==Phase::moving && (opcode==0x11 || opcode==0x28)) {
            const auto decoded=parse_richonline_movement_request(request);
            const auto endpoint=opcode==0x11 ? std::get<RichonlineMoveStop11>(decoded).endpoint :
                std::get<RichonlineMovePause28>(decoded).endpoint;
            if(!movement || opcode!=movement->opcode || endpoint!=movement->endpoint)
                throw CodecError("richonline_classic_endpoint_mismatch");
            const auto checkpoint=next_bank();
            if((opcode==0x28)!=checkpoint.has_value())
                throw CodecError("richonline_classic_bank_checkpoint_mismatch");
            const auto index=checkpoint.value_or(route.landings.size()-1);
            remember(sender,request);
            board.participants[actor].position=route.landings[index];
            board.participants[actor].direction=route.directions[index];
            movement.reset();
            if(checkpoint) return open_bank(RichonlineGameBankVisit::passing,checkpoint);
            route={};route_cursor=0;return land();
        }
        if(phase==Phase::bank && opcode==0x27) {
            auto result=bank->handle(request);remember(sender,request);return bank_result(std::move(result));
        }
        if(phase==Phase::rent_transfer && opcode==0x76) {
            const auto choice=decode_richonline_rent_transfer_choice(request);
            remember(sender,request);return finish_rent_transfer(choice,rules.now()>=rent_transfer->deadline);
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
        if(phase==Phase::bank) {
            if(auto result=bank->poll()) return bank_result(std::move(*result));
        } else if(phase==Phase::rent_transfer) {
            if(rules.now()>=rent_transfer->deadline) return finish_rent_transfer({calendar,-1,0},true);
        } else if(phase==Phase::property) {
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
        disconnected[sender]=true;
        if(!terminal || !terminal->committed())phase=Phase::closed;
        movement.reset();rent_transfer.reset();
        if(raw) {raw->invalidate_actor(sender);raw->invalidate_game();}
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
    if(session->world.stocks) callbacks.stock_action=[session](std::uint8_t actor,const RichonlineStockRequest& request) {
        return broadcast(session->stock_action(actor,request));
    };
    callbacks.poll=[session] {return broadcast(session->poll());};
    callbacks.disconnected=[session](std::uint8_t actor) {session->disconnect(actor);};
    callbacks.retired_action=[session](std::uint8_t actor,View request) {return session->was_retired(actor,request);};
    callbacks.movement_wait=[session] {return session->movement;};
    callbacks.sent=[session](std::uint8_t actor,View plain) {
        if(session->terminal)session->terminal->sent(actor,plain);
    };
    callbacks.game_finished=[session](std::uint8_t actor) {
        return session->terminal && session->terminal->game_finished(actor);
    };
    callbacks.lobby_sent=[session](std::uint8_t actor,const Frame& frame) {
        if(session->terminal)session->terminal->lobby_sent(actor,frame);
    };
    callbacks.terminal_pending=[session](std::uint8_t) {return session->terminal && session->terminal->committed();};
    return callbacks;
}
}

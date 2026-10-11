#include "richonline_classic_session.hpp"
#include "richonline_boss_landing.hpp"
#include "richonline_junction.hpp"
#include "richonline_shop_catalog.hpp"
#include "richonline_collision.hpp"
#include "richonline_raw_authority.hpp"
#include "lua_server.hpp"

#include <algorithm>
#include <bit>
#include <deque>
#include <limits>
#include <utility>

namespace richnet {
namespace {
enum class Phase { loading,roll,moving,bank,property,event,junction,closed };
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
    std::unique_ptr<RichonlineRawAuthority> raw;
    bool collision_pending=false;
    std::unique_ptr<RichonlineGameBank> bank;
    std::optional<RichonlineGameFundsSnapshot> bank_funds;
    std::optional<std::size_t> bank_checkpoint;
    std::size_t route_cursor=0;
    Phase phase=Phase::loading;
    std::uint8_t actor;
    std::uint16_t calendar;
    std::uint64_t sequence=0,completed_rounds=0,movement_sequence=0;
    std::optional<std::uint16_t> pending_opcode;
    std::optional<RichonlineSharedMovementWait> movement;
    std::deque<Retired> retired;
    std::deque<std::pair<std::uint8_t,std::uint16_t>> retired_banks;
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
        raw=std::make_unique<RichonlineRawAuthority>(static_cast<std::uint8_t>(count),board.game_server_id);
        raw->initialize_game();
        for(std::uint8_t slot=0;slot<count;++slot) raw->initialize_actor(slot);
        world.property=std::make_shared<RichonlineClassicProperty>(board.game_server_id,source.topology,
            source.properties,world.ledger,rules.now,rules.decision_timeout,rules.script);
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
            {actor,tile,cell.static_type,cell.property_ref,0,false,degree,occupied,statuses[actor],false,collision_pending},
            board.participants,statuses};
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
            actors.push_back({slot,board.participants[slot].position,true,false,*state.kidnapped1497!=-1,
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
        if(sequence==std::numeric_limits<std::uint64_t>::max())
            throw CodecError("richonline_classic_turn_sequence_overflow");
        // 每条非重播4010加一次日历WORD；轮数只在完整绕回显式起始槽后加一。
        auto packet=encode_richonline_turn4010({board.game_server_id,static_cast<std::int8_t>(actor),
            static_cast<std::int8_t>(rules.first_actor),0},rules.opaque_turn7);
        ++sequence;calendar=static_cast<std::uint16_t>(calendar+1U);
        static_cast<void>(raw->apply_verified_actor_timer_phase(actor,sequence));
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
            *result.pending_opcode==0x27 || *result.pending_opcode==0x28 || *result.pending_opcode==0x34))
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
            throw CodecError("richonline_classic_rent_transfer_unimplemented");
        if(std::string_view(outcome)=="bankrupt")
            throw CodecError("richonline_classic_rent_bankruptcy_unimplemented");
        const auto charged=std::string_view(outcome)=="paid" ? static_cast<std::uint32_t>(amount) : 0U;
        auto payer_after=payer.funds,payee_after=payee.funds;
        if(charged>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max())-*payee_after.deposit)
            throw CodecError("richonline_classic_rent_recipient_overflow");
        const auto cash_paid=std::min(charged,payer_after.cash);
        payer_after.cash-=cash_paid;*payer_after.deposit-=charged-cash_paid;*payee_after.deposit+=charged;
        auto messages=std::vector<Bytes>{stop()};
        const std::array updates{RichonlineGameFundsUpdate{actor,payer,payer_after},
            RichonlineGameFundsUpdate{owner,payee,payee_after}};
        if(!world.ledger->commit_batch(updates,[&]() {
            if(world.cards[actor]->inventory()!=inventory || world.property->snapshot(property.id)!=property) return false;
            if(free_card) world.cards[actor]->commit_inventory(free_card->remaining_inventory);
            return true;
        })) throw CodecError("richonline_classic_rent_commit_stale");
        // 4013已触发客户端6060/6061；只镜像账本/手牌，不发第二笔扣款或扣卡包。
        if(rules.log) rules.log("richonline_classic_rent actor="+std::to_string(actor)+
            " owner="+std::to_string(owner)+" property="+std::to_string(property.id)+
            " sequence="+std::to_string(sequence)+" charged="+std::to_string(charged)+" outcome="+outcome);
        return property_effects(std::move(messages));
    }
    std::vector<Bytes> land() {
        if(collision_pending) throw CodecError("richonline_classic_phase6_already_pending");
        static_cast<void>(collision_actors());
        collision_pending=true;
        const auto current=context();
        // 先完成静态/地产业务，同格效果由complete统一在phase6执行，不能提前抢卡。
        if(auto result=services.landing(current)) return accept_result(std::move(*result));
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
        // 末端传送会改变落点，仍等待专用阶段；途中的银行按原路线检查点逐段汇合。
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
        disconnected[sender]=true;phase=Phase::closed;movement.reset();
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
    callbacks.poll=[session] {return broadcast(session->poll());};
    callbacks.disconnected=[session](std::uint8_t actor) {session->disconnect(actor);};
    callbacks.retired_action=[session](std::uint8_t actor,View request) {return session->was_retired(actor,request);};
    callbacks.movement_wait=[session] {return session->movement;};
    return callbacks;
}
}

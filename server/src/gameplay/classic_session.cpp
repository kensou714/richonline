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
#include "richonline_special_landings.hpp"
#include "richonline_boss_shop.hpp"
#include "richonline_combat_resources.hpp"
#include "richonline_theft_card.hpp"
#include "richonline_classic_interest.hpp"
#include "richonline_fixed_step_card.hpp"
#include "richonline_motion_card.hpp"
#include "richonline_card_protection.hpp"
#include "richonline_classic_funds_card.hpp"
#include "richonline_classic_weapon_treaty.hpp"
#include "richonline_classic_property_card.hpp"
#include "richonline_classic_trade.hpp"
#include "richonline_classic_computer.hpp"
#include "lua_server.hpp"
#include "lua_wire.hpp"

#include <algorithm>
#include <bit>
#include <deque>
#include <limits>
#include <set>
#include <utility>

namespace richnet {
namespace {
enum class Phase { loading,feast_exit,lottery_draw,turn_event,roll,frozen_wait,stationary,kidnap_wait,confinement_wait,confinement_exit,hotel_wait,hotel_exit,moving,bank,shop,lottery,property,research,trade,rent_transfer,event,junction,settling,closed };
enum class Confinement { hospital,jail };
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
struct PendingTrade {
    RichonlineClassicPropertyEntry entry;
    RichonlineClassicPropertyState property;
    RichonlineActorStatus owner_status;
    RichonlineRawActorState owner_raw;
    std::chrono::steady_clock::time_point deadline;
};
struct PreparedHotelEntry {
    RichonlineClassicHotelVisit visit;
    RichonlineRawAuthority::PreparedHotelEntry raw;
};
struct PreparedRetirement {
    RichonlineClassicProperty::Retirement property;
    std::optional<RichonlineStockMarket::Retirement> stocks;
};
struct PendingFeastExit {
    std::uint8_t actor;
    RichonlineFeastRelease kind;
    RichonlineRawActorState before;
    std::int16_t entry,exit;
    std::uint8_t heading;
    bool controlled,complete=false;
    std::chrono::steady_clock::time_point deadline;
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
    std::vector<std::unique_ptr<RichonlineBossShop>> shops;
    std::deque<std::pair<std::uint8_t,std::uint16_t>> retired_shops;
    std::vector<std::shared_ptr<RichonlineGamePayment>> payments;
    std::vector<RichonlinePaidDiceEquipment> payment_equipment;
    std::vector<std::uint64_t> shop_refresh_sequence;
    std::optional<PendingRentTransfer> rent_transfer;
    std::deque<std::pair<std::uint8_t,std::uint16_t>> retired_rent_transfers;
    std::deque<std::pair<std::uint8_t,std::uint16_t>> retired_research;
    std::optional<PendingTrade> trade;
    std::deque<std::pair<std::uint8_t,std::uint16_t>> retired_trades;
    std::deque<std::pair<std::uint8_t,std::uint16_t>> retired_hotels;
    std::vector<std::optional<RichonlineClassicHotelVisit>> hotel_visits;
    std::optional<std::chrono::steady_clock::time_point> hotel_deadline;
    Bytes hotel_wait_packet;
    std::vector<bool> hotel_wait_sent;
    std::chrono::milliseconds hotel_delay{0};
    bool hotel_exit_roll_requested=false,hotel_exit_effects=false;
    std::vector<bool> disconnected;
    std::unique_ptr<RichonlineClassicTerminal> terminal;
    std::vector<Bytes> stock_opening;
    std::uint32_t news_fines=richonline_classic_initial_news_fines;
    std::optional<std::chrono::steady_clock::time_point> kidnap_deadline;
    std::optional<std::chrono::steady_clock::time_point> confinement_deadline;
    bool confinement_exit_roll_requested=false;
    Confinement confinement=Confinement::hospital;
    std::optional<std::chrono::sys_days> last_feast_day;
    std::optional<std::chrono::sys_days> last_interest_day;
    std::vector<PendingFeastExit> feast_exits;
    bool calendar_roll_requested=false;
    std::unique_ptr<RichonlineClassicLottery> lottery;
    std::deque<std::pair<std::uint8_t,std::uint16_t>> retired_lottery;
    std::optional<std::chrono::sys_days> last_lottery_day;
    std::optional<std::chrono::steady_clock::time_point> lottery_draw_deadline;
    Bytes lottery_draw_packet;
    std::vector<bool> lottery_draw_sent;
    std::array<std::optional<std::array<std::uint8_t,6>>,8> accepted_hibernate{};
    std::optional<std::chrono::steady_clock::time_point> frozen_deadline;
    Bytes frozen_wait_packet;
    std::vector<bool> frozen_wait_sent;

    Session(const RichonlineClassicStartup& source,RichonlineClassicSessionRules policy)
        :startup(source),rules(std::move(policy)),board(first_board(source)),
         statuses(board.participants.size()),active(board.participants.size(),1),dice(rules.maximum_dice),
         junction(board.game_server_id),actor(rules.first_actor),round_anchor(rules.first_actor),
         calendar(static_cast<std::uint16_t>(source.recipients.front().snapshot.calendar_counter)),
         disconnected(board.participants.size(),false) {
        const auto count=board.participants.size();
        hotel_visits.resize(count);
        hotel_wait_sent.resize(count,false);
        frozen_wait_sent.resize(count,false);
        if(rules.frozen_turn_delay<std::chrono::milliseconds{1} ||
            rules.frozen_turn_delay>std::chrono::minutes{5} ||
            (rules.hibernate && (!rules.hibernate->frozen_turns || rules.hibernate->frozen_turns>127)))
            throw CodecError("richonline_classic_hibernate_policy_invalid");
        if(count<2 || count>4 || source.players.size()!=count || source.recipients.size()!=count ||
            actor>=count || dice.size()!=count || rules.opening_hands.size()!=count ||
            !rules.random || !rules.now || !rules.card_resources || !rules.resale || !rules.services ||
            rules.decision_timeout<std::chrono::milliseconds{1000} || rules.decision_timeout>std::chrono::minutes{5} ||
            rules.route_wire.local_reserve_charge!=0)
            throw CodecError("richonline_classic_session_policy_invalid");
        const auto& snapshot=source.recipients.front().snapshot;
        const std::chrono::year_month_day start_date{std::chrono::year{board.year},
            std::chrono::month{board.month},std::chrono::day{board.day}};
        if(!start_date.ok() || board.year<2004 || board.year>2034)
            throw CodecError("richonline_classic_interest_date_unsupported");
        if(snapshot.slots.size()!=count || snapshot.game_server_id!=board.game_server_id)
            throw CodecError("richonline_classic_session_snapshot_invalid");
        const auto expected_snapshot=encode_richonline_board_snapshot(snapshot);
        const auto expected_init=encode_richonline_board_init(board);
        if(rules.payment) {
            const auto& policy=*rules.payment;
            if(policy.actors.size()!=count || !policy.equipment)
                throw CodecError("richonline_classic_payment_policy_invalid");
            std::set<std::string> prefixes;
            for(std::size_t slot=0;slot<count;++slot) {
                const auto& member=policy.actors[slot];
                if(member.identity!=source.players[slot].identity || !member.debit || member.operation_prefix.empty() ||
                    member.operation_prefix.size()>128 || member.operation_prefix.find('\0')!=std::string::npos ||
                    !prefixes.insert(member.operation_prefix).second)
                    throw CodecError("richonline_classic_payment_identity_invalid");
                payment_equipment.push_back(policy.equipment->paid_dice_equipment(source.players[slot].equipment));
            }
            if(rules.shop && rules.shop->charges.values!=policy.charges.values)
                throw CodecError("richonline_classic_shop_charge_policy_mismatch");
        }
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
            if(rules.payment) funds.back().reserve=richonline_initial_reserve(
                rules.payment->actors[index].account_gold,source.pawn_gold,rules.payment->charges);
            // NEW初始化附身槽的有符号-1；optional空值表示未知，不能用于地产资格判断。
            statuses[index].possession=-1;
        }
        world.ledger=std::make_shared<RichonlineGameLedger>(std::move(funds));
        if(rules.payment) {
            for(std::uint8_t slot=0;slot<count;++slot) {
                auto payment=std::make_shared<RichonlineGamePayment>(world.ledger,slot,rules.payment->charges,
                    rules.payment->actors[slot].debit);
                for(std::uint8_t dice_count=1;dice_count<=3;++dice_count)
                    static_cast<void>(payment->quote_random_dice(dice_count,payment_equipment[slot]));
                payments.push_back(std::move(payment));
            }
            shop_refresh_sequence.resize(count);
        }
        if(rules.news) {
            if(!rules.news->select)
                throw CodecError("richonline_classic_news_policy_invalid");
        }
        if(rules.hotel) {
            const auto& policy=*rules.hotel;
            if(!policy.result || policy.resources.stay_turns<1 || policy.entry_delay<std::chrono::milliseconds{3600} ||
                policy.turn_delay<std::chrono::milliseconds{1800} || policy.controlled_exit_delay<std::chrono::milliseconds{900} ||
                policy.exit_timeout<policy.controlled_exit_delay)
                throw CodecError("richonline_classic_hotel_policy_invalid");
            for(const auto delay:{policy.entry_delay,policy.turn_delay,policy.controlled_exit_delay,policy.exit_timeout})
                if(delay>std::chrono::minutes{5}) throw CodecError("richonline_classic_hotel_policy_invalid");
        }
        if(rules.kidnap && (!rules.kidnap->return_position ||
            rules.kidnap->entry_delay<std::chrono::seconds{1} || rules.kidnap->entry_delay>std::chrono::seconds{30} ||
            rules.kidnap->turn_delay<std::chrono::seconds{1} || rules.kidnap->turn_delay>std::chrono::seconds{30}))
            throw CodecError("richonline_classic_kidnap_policy_invalid");
        for(const auto* policy:{rules.hospital ? static_cast<const RichonlineClassicConfinementPolicy*>(&*rules.hospital) : nullptr,
            rules.jail ? static_cast<const RichonlineClassicConfinementPolicy*>(&*rules.jail) : nullptr}) {
            if(!policy) continue;
            for(const auto delay:{policy->entry_delay,policy->turn_delay,policy->controlled_exit_delay,policy->exit_timeout})
                if(delay<std::chrono::milliseconds{1} || delay>std::chrono::minutes{5})
                    throw CodecError("richonline_classic_confinement_policy_invalid");
        }
        raw=std::make_unique<RichonlineRawAuthority>(static_cast<std::uint8_t>(count),board.game_server_id);
        raw->initialize_game();
        for(std::uint8_t slot=0;slot<count;++slot) raw->initialize_actor(slot);
        if(rules.feasts) {
            const auto& policy=*rules.feasts;
            if(!policy.resources || policy.controlled_exit_delay<std::chrono::milliseconds{1} ||
                policy.controlled_exit_delay>std::chrono::minutes{5} ||
                policy.exit_timeout<policy.controlled_exit_delay || policy.exit_timeout>std::chrono::minutes{5})
                throw CodecError("richonline_classic_feast_policy_invalid");
            static_cast<void>(policy.resources->find({std::chrono::year{board.year},
                std::chrono::month{board.month},std::chrono::day{board.day}}));
        }
        if(rules.lottery) {
            if(!rules.feasts || rules.lottery->draw_delay<std::chrono::milliseconds{6400} ||
                rules.lottery->draw_delay>std::chrono::minutes{5} || board.year<2004 || board.year>2034)
                throw CodecError("richonline_classic_lottery_policy_invalid");
            lottery=std::make_unique<RichonlineClassicLottery>(board.game_server_id,world.ledger,rules.now,
                rules.decision_timeout,rules.random,rules.lottery->draw_opaque,rules.script);
            lottery_draw_sent.resize(count,false);
        }
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
        std::optional<RichonlineClassicBuildingPolicy> buildings;
        if(rules.buildings) buildings=RichonlineClassicBuildingPolicy{rules.buildings,world.cards,
            rules.secondary_building_licence_absent};
        world.property=std::make_shared<RichonlineClassicProperty>(board.game_server_id,source.topology,
            source.properties,world.ledger,rules.now,rules.decision_timeout,rules.script,std::move(buildings));
        if(rules.research) world.research=std::make_shared<RichonlineClassicResearch>(board.game_server_id,
            source.topology,source.properties,world.property,world.cards,rules.card_resources,
            rules.now,rules.decision_timeout,rules.script);
        services=rules.services(world);
        if(!services.landing || !services.property_effects || !services.event || !services.poll ||
            ((world.research || rules.feasts || lottery) && !services.turn_start)) {
            release_members();
            throw CodecError("richonline_classic_session_services_incomplete");
        }
        try {
            if(!payments.empty() && services.shop_refresh)
                throw CodecError("richonline_classic_payment_owner_ambiguous");
            if(rules.shop) {
                for(std::uint8_t slot=0;slot<count;++slot) {
                    auto shop=std::make_unique<RichonlineBossShop>(*rules.resale,*world.cards[slot],
                        board.game_server_id,world.ledger,rules.now,rules.shop->stock_opaque,rules.random);
                    RichonlineBossShop::ChargeReserve charge;
                    if(!payments.empty()) charge=[this,slot](std::uint32_t amount) {
                        if(amount!=static_cast<std::uint32_t>(rules.payment->charges.require(4)))
                            throw CodecError("richonline_classic_shop_charge_mismatch");
                        auto& next_refresh=shop_refresh_sequence[slot];
                        if(next_refresh==std::numeric_limits<std::uint64_t>::max())
                            throw CodecError("richonline_classic_payment_sequence_overflow");
                        const auto operation=rules.payment->actors[slot].operation_prefix+":shop:"+std::to_string(++next_refresh);
                        return payment_committed(payments[slot]->shop_refresh(operation));
                    };
                    else if(services.shop_refresh) charge=[refresh=services.shop_refresh,slot](std::uint32_t amount) {
                        return refresh(slot,amount);
                    };
                    shop->configure_refresh(rules.shop->charges,std::move(charge));
                    shops.push_back(std::move(shop));
                }
            }
            if(rules.settlement) {
                terminal=rules.settlement(world);
                if(!terminal)throw CodecError("richonline_classic_terminal_missing");
                terminal->validate_identity(board.game_server_id,startup.room.key,board.participants,startup.pawn_gold,world.ledger.get());
            }
            if(rules.asset_settlement) {
                const auto& policy=*rules.asset_settlement;
                if(!terminal || !world.stocks || !policy.property_value || policy.evidence.empty() ||
                    policy.evidence.size()>512 || policy.evidence.find('\0')!=std::string::npos)
                    throw CodecError("richonline_classic_asset_policy_incomplete");
                terminal->validate_month_limit(active);
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
            if(other!=actor && active[other] && raw->actor(static_cast<std::uint8_t>(other)).kidnapped1497==-1 &&
                board.participants[other].position==tile) occupied=true;
        return {board.game_server_id,calendar,sequence,completed_rounds,
            {actor,tile,cell.static_type,cell.property_ref,0,false,degree,occupied,statuses[actor],false,collision_pending},
            board.participants,statuses,active,round_anchor};
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
        if(request.size()>=2 && read_le(request.first(2))==0x26) {
            const auto day=decode_richonline_classic_hotel_request(request);
            if(std::ranges::find(retired_hotels,std::pair{sender,day})!=retired_hotels.end()) return true;
        }
        if(request.size()>=2 && read_le(request.first(2))==0x25) {
            const auto day=decode_richonline_classic_trade_request(request);
            if(std::ranges::find(retired_trades,std::pair{sender,day})!=retired_trades.end()) return true;
        }
        if(request.size()>=2 && read_le(request.first(2))==0x29) {
            const auto choice=decode_richonline_lottery_request(request);
            if(std::ranges::find(retired_lottery,std::pair{sender,choice.calendar})!=retired_lottery.end()) return true;
        }
        if(request.size()>=2 && read_le(request.first(2))==0x24) {
            const auto choice=decode_richonline_classic_research_request(request);
            if(std::ranges::find(retired_research,std::pair{sender,choice.calendar})!=retired_research.end()) return true;
        }
        if(request.size()>=4) {
            const auto opcode=read_le(request.first(2));
            const auto turn=static_cast<std::uint16_t>(read_le(request.subspan(2,2)));
            if((((opcode==0x30 || opcode==0x31) && request.size()==6) || (opcode==0x35 && request.size()==4)) &&
                std::ranges::find(retired_shops,std::pair{sender,turn})!=retired_shops.end()) return true;
        }
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
        std::vector<Bytes> messages{std::move(packet)};
        if(statuses[actor].stay && movement_sequence==std::numeric_limits<std::uint64_t>::max())
            throw CodecError("richonline_classic_movement_sequence_overflow");
        ++sequence;calendar=static_cast<std::uint16_t>(calendar+1U);
        static_cast<void>(raw->apply_verified_actor_timer_phase(actor,sequence));
        richonline_status_begin_active_turn(statuses[actor]);
        accepted_hibernate={};frozen_deadline.reset();frozen_wait_packet.clear();
        phase=Phase::roll;pending_opcode.reset();kidnap_deadline.reset();confinement_deadline.reset();
        hotel_deadline.reset();hotel_wait_packet.clear();hotel_exit_roll_requested=false;hotel_exit_effects=false;
        confinement_exit_roll_requested=false;
        calendar_roll_requested=false;
        // 7C0C50轮首先推进日期再递减查封/涨价；初始锚点只初始化日历，不进入递减块。
        if(actor==round_anchor && completed_rounds) world.property->advance_street_effects(completed_rounds);
        apply_monthly_interest();
        return begin_feast(std::move(messages));
    }
    void apply_monthly_interest() {
        if(actor!=round_anchor) return;
        const std::chrono::sys_days start{std::chrono::year{board.year}/board.month/board.day};
        const std::chrono::sys_days last{std::chrono::year{2034}/12/31};
        // 客户端超出2034年会回退本机年份；没有同步依据时不可继续外推。
        if(completed_rounds>static_cast<std::uint64_t>((last-start).count()))
            throw CodecError("richonline_classic_interest_date_unsupported");
        const auto date=start+std::chrono::days{static_cast<std::int64_t>(completed_rounds)};
        if(last_interest_day==date || std::chrono::year_month_day{date}.day()!=std::chrono::day{1}) return;
        // 首次轮首只种日历计数，不推进日期，故开局恰逢1日同样加息。
        // 这一步先于节日且不受scripted_event门限制，所有活动角色共同入账。
        const auto updates=prepare_richonline_classic_interest(active,*world.ledger,rules.script);
        if(!world.ledger->commit_batch(updates,[] {return true;}))
            throw CodecError("richonline_classic_interest_commit_rejected");
        last_interest_day=date;
    }
    std::vector<Bytes> after_feast(std::vector<Bytes> messages) {
        // 7C0C50的selector3开奖门只有日期15、轮首和已有号码，不复用节日的脚本事件门。
        if(lottery && actor==round_anchor) {
            const std::chrono::sys_days start{std::chrono::year{board.year}/board.month/board.day};
            const std::chrono::sys_days last{std::chrono::year{2034}/12/31};
            if(completed_rounds>static_cast<std::uint64_t>((last-start).count()))
                throw CodecError("richonline_lottery_date_unsupported");
            const auto date=start+std::chrono::days{static_cast<std::int64_t>(completed_rounds)};
            if(last_lottery_day!=date && std::chrono::year_month_day{date}.day()==std::chrono::day{15}) {
                // 为报文和发送跟踪预留空间，派奖事务成功后不再因vector增长丢失回复。
                messages.reserve(messages.size()+1);lottery_draw_packet.reserve(12);
                if(auto draw=lottery->draw(sequence,active,news_fines)) {
                    last_lottery_day=date;phase=Phase::lottery_draw;
                    lottery_draw_packet=draw->message;
                    std::fill(lottery_draw_sent.begin(),lottery_draw_sent.end(),false);
                    lottery_draw_deadline.reset();messages.push_back(std::move(draw->message));
                    if(rules.log) rules.log("richonline_classic_lottery_draw number="+std::to_string(draw->number)+
                        " winner="+std::to_string(draw->winner)+" prize="+std::to_string(draw->prize)+
                        " next_pool="+std::to_string(news_fines)+" sequence="+std::to_string(sequence));
                    return messages;
                }
                last_lottery_day=date;
            }
        }
        return after_lottery(std::move(messages));
    }
    std::vector<Bytes> after_lottery(std::vector<Bytes> messages) {
        if(services.turn_start) return turn_start_result(std::move(messages),services.turn_start(context()));
        return finish_turn_start(std::move(messages));
    }
    std::vector<Bytes> begin_feast(std::vector<Bytes> messages) {
        if(!rules.feasts || actor!=round_anchor) return after_feast(std::move(messages));
        if(!feast_exits.empty()) throw CodecError("richonline_classic_feast_exit_pending");
        const auto scripted=raw->game().scripted_event83830;
        if(!scripted) throw CodecError("richonline_classic_feast_game_unknown");
        if(*scripted!=-1) return after_feast(std::move(messages));
        const std::chrono::sys_days start{std::chrono::year{board.year}/board.month/board.day};
        const std::chrono::sys_days last{std::chrono::year{2034}/12/31};
        if(completed_rounds>static_cast<std::uint64_t>((last-start).count()))
            throw CodecError("richonline_feast_date_unsupported");
        const auto date=start+std::chrono::days{static_cast<std::int64_t>(completed_rounds)};
        if(last_feast_day==date) return after_feast(std::move(messages));
        const auto slot=rules.feasts->resources->find(std::chrono::year_month_day{date});
        if(!slot) {last_feast_day=date;return after_feast(std::move(messages));}
        const auto plan=prepare_richonline_classic_feast(*slot,board.game_server_id,active,statuses,
            *raw,*world.ledger,world.cards,rules.random,rules.script);
        std::vector<PendingFeastExit> exits;
        std::vector<RichonlineGameFundsUpdate> funds;
        const auto now=rules.now();
        for(const auto& change:plan.changes) {
            funds.push_back({change.actor,change.before_funds,change.after_funds});
            if(change.release==RichonlineFeastRelease::none) continue;
            const auto pair=change.release==RichonlineFeastRelease::hospital ?
                startup.topology.hospital_positions() : startup.topology.jail_positions();
            if(!pair || board.participants[change.actor].position!=(*pair)[0] ||
                !startup.topology.cell((*pair)[1]).walkable)
                throw CodecError("richonline_classic_feast_exit_geometry");
            const auto width=static_cast<std::int32_t>(startup.topology.width());
            const auto dx=(*pair)[1]%width-(*pair)[0]%width,dy=(*pair)[1]/width-(*pair)[0]/width;
            const auto controlled=change.after_status.possession==7 || change.after_status.sleepwalking!=0;
            exits.push_back({change.actor,change.release,change.before_raw,(*pair)[0],(*pair)[1],
                static_cast<std::uint8_t>(dy>0 ? 0 : dx<0 ? 1 : dy<0 ? 2 : 3),controlled,false,
                now+(controlled ? rules.feasts->controlled_exit_delay : rules.feasts->exit_timeout)});
        }
        // 所有准备和消息分配均在提交前完成。各人独立手牌及本地状态与资金同笔生效。
        messages.insert(messages.end(),plan.messages.begin(),plan.messages.end());
        for(const auto& change:plan.changes)
            if(raw->actor(change.actor)!=change.before_raw || statuses[change.actor]!=change.before_status ||
                world.cards[change.actor]->inventory()!=change.before_inventory)
                throw CodecError("richonline_classic_feast_state_stale");
        if(!world.ledger->commit_batch(funds,[&]() noexcept {
            for(const auto& change:plan.changes) {
                world.cards[change.actor]->commit_inventory(change.after_inventory);
                statuses[change.actor]=change.after_status;
            }
            return true;
        })) throw CodecError("richonline_classic_feast_funds_stale");
        last_feast_day=date;feast_exits.swap(exits);
        if(rules.log) rules.log("richonline_classic_feast slot="+std::to_string(*slot)+
            " round="+std::to_string(completed_rounds)+" anchor="+std::to_string(round_anchor)+
            " exits="+std::to_string(feast_exits.size())+" response_count="+std::to_string(plan.messages.size()));
        if(feast_exits.empty()) return after_feast(std::move(messages));
        phase=Phase::feast_exit;return messages;
    }
    void complete_feast_exit(PendingFeastExit& exit) {
        if(exit.complete || !active[exit.actor] || raw->actor(exit.actor)!=exit.before ||
            board.participants[exit.actor].position!=exit.entry)
            throw CodecError("richonline_classic_feast_exit_stale");
        // 631640/631D20清收容，631800/631EE0归位出口；不触发出口格或推进日历。
        if(exit.kind==RichonlineFeastRelease::hospital) raw->exit_hospital(exit.actor);
        else raw->exit_jail(exit.actor);
        board.participants[exit.actor].position=exit.exit;
        board.participants[exit.actor].direction=exit.heading;
        exit.complete=true;
    }
    std::vector<Bytes> continue_feast_exits() {
        if(std::ranges::any_of(feast_exits,[](const auto& exit){return !exit.complete;})) return {};
        feast_exits.clear();return after_feast({});
    }
    static bool reserved_event(std::uint16_t opcode) noexcept {
        return opcode==0x10 || opcode==0x11 || opcode==0x14 || opcode==0x15 || opcode==0x20 || opcode==0x21 ||
            opcode==0x23 || opcode==0x24 || opcode==0x25 || opcode==0x26 || opcode==0x27 || opcode==0x28 || opcode==0x29 || opcode==0x34 || opcode==0x76;
    }
    std::vector<Bytes> turn_start_result(std::vector<Bytes> prefix,RichonlineLandingResult result) {
        if((result.progress!=RichonlineLandingProgress::complete && result.progress!=RichonlineLandingProgress::await_event) ||
            (result.progress==RichonlineLandingProgress::await_event)!=result.pending_opcode.has_value() ||
            (result.pending_opcode && reserved_event(*result.pending_opcode)) || result.temple_change || result.status_change)
            throw CodecError("richonline_classic_turn_continuation_invalid");
        for(const auto& packet:result.messages) {
            if(packet.size()<2) throw CodecError("richonline_classic_turn_continuation_packet_invalid");
            const auto opcode=read_le(View(packet).first(2));
            if(opcode==0x4010 || opcode==0x420f || (rules.feasts && (opcode==0x40a0 || opcode==0x40a1)) ||
                (lottery && opcode==0x402c))
                throw CodecError("richonline_classic_turn_continuation_packet_invalid");
        }
        append(prefix,std::move(result.messages));
        if(result.pending_opcode) {
            phase=Phase::turn_event;pending_opcode=result.pending_opcode;return prefix;
        }
        return finish_turn_start(std::move(prefix));
    }
    std::vector<Bytes> finish_turn_start(std::vector<Bytes> messages) {
        // 日历事件完成才同步客户端7E4C50的本次扫描；重播同一回合不会重复发卡。
        if(world.research) {
            const auto scan=world.research->advance(actor,sequence);
            if(rules.log && (scan.completed || scan.cancelled))
                rules.log("richonline_classic_research_scan actor="+std::to_string(actor)+
                    " sequence="+std::to_string(sequence)+" completed="+std::to_string(scan.completed)+
                    " cancelled="+std::to_string(scan.cancelled)+" discarded_full="+std::to_string(scan.discarded_full));
        }
        phase=Phase::roll;pending_opcode.reset();
        const auto hotel=raw->actor(actor).hotel1493;
        if(!hotel || (*hotel>=0)!=hotel_visits[actor].has_value())
            throw CodecError("richonline_classic_hotel_state_invalid");
        if(*hotel>=0) {
            if(!rules.hotel) throw CodecError("richonline_classic_hotel_policy_missing");
            const auto& visit=*hotel_visits[actor];
            const auto property=world.property->snapshot(visit.property);
            if(board.participants[actor].position!=visit.inside)
                throw CodecError("richonline_classic_hotel_position_stale");
            // 7F7F60从备份道路格找地产：建筑归零或改成非饭店立即出店，不查产权/查封。
            const bool exit=*hotel==0 || property.level==0 || property.kind!=4;
            phase=exit ? Phase::hotel_exit : Phase::hotel_wait;
            hotel_exit_roll_requested=false;
            route={};route_cursor=0;movement.reset();
            messages.push_back(encode_richonline_empty_turn420f(board.game_server_id));
            arm_hotel_delay(messages.back(),exit ? (confinement_controlled() ? rules.hotel->controlled_exit_delay :
                rules.hotel->exit_timeout) : rules.hotel->turn_delay);
            if(rules.log) rules.log("richonline_classic_hotel_turn actor="+std::to_string(actor)+
                " days="+std::to_string(*hotel)+" exiting="+std::to_string(exit)+
                " property="+std::to_string(visit.property));
            return messages;
        }
        const auto hospital=raw->actor(actor).hospital1494;
        const auto jail=raw->actor(actor).jail1495;
        if(!hospital || !jail || (*hospital>=0 && *jail>=0))
            throw CodecError("richonline_classic_confinement_state_invalid");
        if(*hospital>=0 || *jail>=0) {
            confinement=*hospital>=0 ? Confinement::hospital : Confinement::jail;
            const auto days=*hospital>=0 ? *hospital : *jail;
            const auto& policy=confinement_policy();
            static_cast<void>(confinement_positions());
            route={};route_cursor=0;movement.reset();
            // 收容入口不是道路。这里只进入阶段4提示/退出动画，不构造该格落点context。
            messages.push_back(encode_richonline_empty_turn420f(board.game_server_id));
            phase=days==0 ? Phase::confinement_exit : Phase::confinement_wait;
            confinement_deadline=rules.now()+(days>0 ? policy.turn_delay :
                confinement_controlled() ? policy.controlled_exit_delay : policy.exit_timeout);
            if(rules.log) rules.log("richonline_classic_confinement_turn actor="+std::to_string(actor)+
                " calendar="+std::to_string(calendar)+" days="+std::to_string(days)+
                " jail="+std::to_string(confinement==Confinement::jail));
            return messages;
        }
        const auto kidnapped=raw->actor(actor).kidnapped1497;
        if(!kidnapped) throw CodecError("richonline_classic_kidnap_state_unknown");
        if(*kidnapped>=0) {
            if(!rules.kidnap) throw CodecError("richonline_classic_kidnap_policy_missing");
            route={};route_cursor=0;movement.reset();
            if(*kidnapped==0) {
                const auto before=context();
                const auto raw_before=raw->actor(actor);
                const auto position=rules.kidnap->return_position(before);
                const auto& cell=startup.topology.cell(position);
                if(!cell.walkable || std::ranges::none_of(cell.neighbors,[](const auto& next){return next.has_value();}))
                    throw CodecError("richonline_classic_kidnap_return_position_invalid");
                auto returning=prepare_richonline_classic_kidnap_return(board.game_server_id,position,rules.script);
                messages.push_back(std::move(returning));
                if(raw->actor(actor)!=raw_before || statuses[actor]!=before.landing.actor_status ||
                    board.participants[actor].position!=before.landing.position)
                    throw CodecError("richonline_classic_kidnap_return_stale");
                raw->exit_kidnapped(actor);board.participants[actor].position=position;
                // 4008已经排阶段6行动界面；不重复420F，不触发返回格的落点效果。
            } else {
                messages.push_back(encode_richonline_empty_turn420f(board.game_server_id));
                phase=Phase::kidnap_wait;kidnap_deadline=rules.now()+rules.kidnap->turn_delay;
            }
            if(rules.log) rules.log("richonline_classic_kidnap_turn actor="+std::to_string(actor)+
                " sequence="+std::to_string(sequence)+" days="+std::to_string(*kidnapped)+
                " position="+std::to_string(board.participants[actor].position));
            return messages;
        }
        messages.push_back(encode_richonline_empty_turn420f(board.game_server_id));
        if(statuses[actor].frozen) {
            // 7C0C50先递减1500，再于阶段4排1800ms提示并返回；不发送0011。
            // 冰冻优先于停走/梦游，不触发本格落点或同格碰撞，等待由整局持有。
            phase=Phase::frozen_wait;route={};route_cursor=0;movement.reset();
            frozen_wait_packet=messages.back();frozen_deadline.reset();
            std::fill(frozen_wait_sent.begin(),frozen_wait_sent.end(),false);
            calendar_roll_requested=false;
            if(rules.log) rules.log("richonline_classic_frozen_turn actor="+std::to_string(actor)+
                " remaining="+std::to_string(statuses[actor].frozen)+" sequence="+std::to_string(sequence));
            return messages;
        }
        if(statuses[actor].stay) {
            // 客户端不掷骰、不发4011；每个连接直接回报0011和当前原位置。
            route={};route_cursor=0;phase=Phase::stationary;
            movement=RichonlineSharedMovementWait{++movement_sequence,calendar,
                board.participants[actor].position,actor,0x11};
        }
        if(rules.log) rules.log("richonline_classic_turn actor="+std::to_string(actor)+
            " sequence="+std::to_string(sequence)+" calendar="+std::to_string(calendar));
        if(std::exchange(calendar_roll_requested,false) && phase==Phase::roll) append(messages,random_move({}));
        return messages;
    }
    bool confinement_controlled() const noexcept {
        return statuses[actor].possession==7 || statuses[actor].sleepwalking!=0;
    }
    std::optional<PreparedHotelEntry> prepare_hotel_entry() const {
        if(!rules.hotel) throw CodecError("richonline_classic_hotel_policy_missing");
        // 67F000/6712B0的type2只排除冰冻；免费、财神、梦游不会免除住店。
        if(statuses[actor].frozen) return {};
        if(hotel_visits[actor]) throw CodecError("richonline_classic_hotel_already_entered");
        const auto road=board.participants[actor].position;
        return PreparedHotelEntry{prepare_richonline_classic_hotel_visit(startup.topology,road,
            startup.topology.cell(road).property_ref,rules.script),
            raw->prepare_hotel_entry(actor,rules.hotel->resources.stay_turns)};
    }
    bool commit_hotel_entry(PreparedHotelEntry& plan) noexcept {
        if(!raw->commit_hotel_entry(plan.raw)) return false;
        hotel_visits[actor]=plan.visit;
        statuses[actor].stay=0;
        board.participants[actor].position=plan.visit.inside;
        board.participants[actor].direction=plan.visit.heading;
        return true;
    }
    void arm_hotel_delay(const Bytes& packet,std::chrono::milliseconds delay) {
        hotel_wait_packet=packet;hotel_delay=delay;hotel_deadline.reset();
        std::fill(hotel_wait_sent.begin(),hotel_wait_sent.end(),false);
    }
    std::vector<Bytes> hotel_payment_complete(std::vector<Bytes> messages) {
        // 6043/type2结束后不再排phase6；6066入店动画无0011位置回报。
        // 冰冻时无入店动画，同样不能私自补碰撞或地产附加效果。
        collision_pending=false;pending_opcode.reset();phase=Phase::hotel_wait;
        arm_hotel_delay(messages.front(),rules.hotel->entry_delay);
        if(rules.log) rules.log("richonline_classic_hotel_paid actor="+std::to_string(actor)+
            " entered="+std::to_string(hotel_visits[actor].has_value())+
            " position="+std::to_string(board.participants[actor].position));
        return messages;
    }
    std::vector<Bytes> hotel_exit_ready(std::vector<Bytes> messages) {
        hotel_exit_effects=false;phase=Phase::roll;pending_opcode.reset();
        if(std::exchange(hotel_exit_roll_requested,false)) append(messages,random_move({}));
        return messages;
    }
    std::vector<Bytes> finish_hotel_exit() {
        if(phase!=Phase::hotel_exit || !hotel_visits[actor] || !rules.hotel)
            throw CodecError("richonline_classic_hotel_exit_invalid");
        const auto visit=*hotel_visits[actor];
        const auto hotel=raw->actor(actor).hotel1493;
        const auto property=world.property->snapshot(visit.property);
        if(!hotel || *hotel<0 || (*hotel!=0 && property.kind==4 && property.level>0) ||
            board.participants[actor].position!=visit.inside)
            throw CodecError("richonline_classic_hotel_exit_stale");
        raw->exit_hotel(actor);
        board.participants[actor].position=visit.road;
        board.participants[actor].direction=static_cast<std::uint8_t>((visit.heading+2U)%4U);
        hotel_visits[actor].reset();hotel_deadline.reset();hotel_wait_packet.clear();hotel_exit_effects=true;
        if(rules.log) rules.log("richonline_classic_hotel_exit actor="+std::to_string(actor)+
            " road="+std::to_string(visit.road)+" property="+std::to_string(visit.property));
        // 630CC0恢复原道路，6084(4,0,0)只执行附加效果；完成后恢复同一玩家行动。
        // 若附加效果要等事件，accept_result保留hotel_exit_effects直到该事件完成。
        return property_effects({});
    }
    const RichonlineClassicConfinementPolicy& confinement_policy() const {
        if(confinement==Confinement::hospital && rules.hospital) return *rules.hospital;
        if(confinement==Confinement::jail && rules.jail) return *rules.jail;
        throw CodecError("richonline_classic_confinement_policy_missing");
    }
    std::array<std::int16_t,2> confinement_positions() const {
        const auto& pair=confinement==Confinement::hospital ? startup.topology.hospital_positions() :
            startup.topology.jail_positions();
        if(!pair) throw CodecError("richonline_classic_confinement_positions_missing");
        return *pair;
    }
    std::vector<Bytes> finish_confinement_exit() {
        const auto days=confinement==Confinement::hospital ? raw->actor(actor).hospital1494 : raw->actor(actor).jail1495;
        if(phase!=Phase::confinement_exit || days!=0)
            throw CodecError("richonline_classic_confinement_exit_invalid");
        const auto pair=confinement_positions();
        const auto width=static_cast<std::int32_t>(startup.topology.width());
        const auto dx=pair[1]%width-pair[0]%width,dy=pair[1]/width-pair[0]/width;
        if(confinement==Confinement::hospital) raw->exit_hospital(actor);
        else raw->exit_jail(actor);
        board.participants[actor].position=pair[1];
        board.participants[actor].direction=static_cast<std::uint8_t>(dy>0 ? 0 : dx<0 ? 1 : dy<0 ? 2 : 3);
        confinement_deadline.reset();phase=Phase::roll;
        if(rules.log) rules.log("richonline_classic_confinement_exit actor="+std::to_string(actor)+
            " calendar="+std::to_string(calendar)+" position="+std::to_string(pair[1]));
        // 医院631640/631800、监狱631D20/631EE0及阶段4已恢复行动界面。
        // 不重复420F、stay或出口落点事件。
        if(std::exchange(confinement_exit_roll_requested,false)) {
            return random_move({});
        }
        return {};
    }
    std::vector<Bytes> opening() {
        if(phase!=Phase::loading) throw CodecError("richonline_classic_opening_repeated");
        auto messages=opening_hands.synchronization;
        // 全员收齐4200及每槽4201后，共享宿主才调用stock_action；只发送一次历史。
        messages.insert(messages.end(),stock_opening.begin(),stock_opening.end());
        // 轮首日历及研究奖励读取同一手牌；起手牌先入权威库存，不能最后覆盖轮首奖励。
        for(std::size_t slot=0;slot<world.cards.size();++slot)
            world.cards[slot]->commit_inventory(opening_hands.inventories[slot]);
        append(messages,begin_turn());
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
        // 月数在客户端转为BYTE天数；到期先冻结资产，不再执行新回合扣减或掷骰。
        const auto limit=static_cast<std::uint8_t>(startup.game_months*30U);
        if(next==round_anchor && limit && completed_rounds+2>limit)
            return finish_month_limit(std::move(messages),next);
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
        if(result.pending_opcode && reserved_event(*result.pending_opcode))
            throw CodecError("richonline_classic_continuation_reserved_opcode");
        if(result.status_change) {
            if(result.status_change->expected!=statuses[actor])
                throw CodecError("richonline_classic_continuation_status_stale");
            // 外部落点回调不得绕过各卡牌、NPC和受控状态的独立事务。
            if(result.status_change->updated!=statuses[actor])
                throw CodecError("richonline_classic_status_continuation_unimplemented");
        }
        if(result.progress==RichonlineLandingProgress::await_event) {
            phase=Phase::event;pending_opcode=result.pending_opcode;return std::move(result.messages);
        }
        if(hotel_exit_effects) return hotel_exit_ready(std::move(result.messages));
        return complete(std::move(result.messages));
    }
    RichonlineClassicPropertyEntry property_entry() const {
        const auto current=context();
        const auto land=startup.players[actor].equipment[2];
        if(land>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
            throw CodecError("richonline_classic_land_equipment_invalid");
        return {board.game_server_id,calendar,sequence,actor,current.landing.position,
            current.landing.property_ref,static_cast<std::int32_t>(land),statuses[actor],
            world.property->snapshot(current.landing.property_ref).sealed_days!=0};
    }
    std::vector<Bytes> property_effects(std::vector<Bytes> prefix) {
        auto result=services.property_effects(context());
        prefix.insert(prefix.end(),std::make_move_iterator(result.messages.begin()),std::make_move_iterator(result.messages.end()));
        result.messages=std::move(prefix);return accept_result(std::move(result));
    }
    void apply_estate_effect(std::int16_t property) {
        const auto source=world.property->snapshot(property);
        if(source.sprite_type!=12 || source.kind!=6 || !source.owner)
            throw CodecError("richonline_classic_estate_source_invalid");
        const bool own=*source.owner==actor;
        const auto plan=world.property->prepare_estate_effect(property,actor);
        std::int16_t target=-1;unsigned level=0;
        for(std::size_t index=0;index<plan.before().size();++index)
            if(plan.before()[index]!=plan.after()[index]) {
                target=plan.after()[index].id;level=plan.after()[index].level;break;
            }
        const auto detail="richonline_classic_estate actor="+std::to_string(actor)+
            " property="+std::to_string(property)+" improve="+std::to_string(own)+
            " target="+std::to_string(target)+" level="+std::to_string(level)+
            " sequence="+std::to_string(sequence);
        if(!world.property->commit_card_change(plan))
            throw CodecError("richonline_classic_estate_commit_stale");
        if(rules.log) rules.log(detail);
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
        const RichonlineGameFundsSnapshot& payee,Bytes entry_packet,
        RichonlineRentTransferKind kind) {
        if(rent_transfer || !property.owner) throw CodecError("richonline_classic_rent_transfer_already_pending");
        std::int8_t card_slot=-1;
        for(std::size_t index=0;index<inventory.size();++index) if(inventory[index].card_id==1056) {
            if(inventory[index].count<=0) throw CodecError("richonline_classic_rent_transfer_card_invalid");
            card_slot=static_cast<std::int8_t>(index);break;
        }
        if(card_slot<0) throw CodecError("richonline_classic_rent_transfer_card_missing");
        RichonlineRentTransferState state{board.game_server_id,calendar,actor,*property.owner,amount,{},
            rent_transfer_targets(),inventory,card_slot,kind};
        for(std::uint8_t slot=0;slot<board.participants.size();++slot) state.funds.push_back(world.ledger->snapshot(slot));
        if(state.funds[actor]!=payer || state.funds[*property.owner]!=payee ||
            world.cards[actor]->inventory()!=inventory || world.property->snapshot(property.id)!=property)
            throw CodecError("richonline_classic_rent_transfer_entry_stale");
        auto messages=std::vector<Bytes>{std::move(entry_packet)};
        // 贸易中心4027先暂停客户端队列3600ms，再显示UI27；给等待保留这段动画时间。
        const auto delay=kind!=RichonlineRentTransferKind::rent ? std::chrono::milliseconds{3600} :
            std::chrono::milliseconds{0};
        rent_transfer=PendingRentTransfer{std::move(state),property,board.participants[actor].position,sequence,
            rules.now()+rules.decision_timeout+delay};
        phase=Phase::rent_transfer;pending_opcode=0x76;
        // 4013/type0或4027/type1使客户端缓存同一金额并排608C，只有原付款人打开UI27。
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
        const bool hotel=pending.state.kind==RichonlineRentTransferKind::hotel;
        auto hotel_entry=hotel && (!plan.bankrupt || plan.payer!=actor) ? prepare_hotel_entry() :
            std::optional<PreparedHotelEntry>{};
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
            if(hotel_entry && !raw->matches_hotel_entry(hotel_entry->raw)) return false;
            if(retirement && !commit_retirement(*retirement)) return false;
            if(retirement) retire_actor(plan.payer);
            if(hotel_entry && !commit_hotel_entry(*hotel_entry)) std::terminate();
            world.cards[actor]->commit_inventory(plan.inventory);return true;
        })) throw CodecError("richonline_classic_rent_transfer_commit_stale");
        rent_transfer.reset();pending_opcode.reset();
        if(retirement && std::ranges::count(active,std::uint8_t{1})==1)
            return finish_last_survivor(std::move(messages),plan.payer);
        if(rules.log) rules.log("richonline_classic_rent_transfer actor="+std::to_string(actor)+
            " payer="+std::to_string(plan.payer)+" charged="+std::to_string(plan.charged)+
            " target="+std::to_string(plan.target)+" timed_out="+std::to_string(timed_out)+
            " sequence="+std::to_string(sequence));
        // 40C6(type0/1)排6080(2,5)，只进入附加效果，不再调用收费入口或补第二条4013。
        if(!active[actor]) {collision_pending=false;return advance(std::move(messages));}
        if(hotel) return hotel_payment_complete(std::move(messages));
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
            validate_month_limit(after);
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
        if(world.research) world.research->retire(plan.property.actor());
        if(lottery) lottery->retire(plan.property.actor());
        return true;
    }
    void validate_month_limit(std::span<const std::uint8_t> survivors) const {
        if(!terminal || !rules.asset_settlement || !world.stocks)
            throw CodecError("richonline_classic_month_settlement_unimplemented");
        terminal->validate_month_limit(survivors);
    }
    std::vector<Bytes> finish_month_limit(std::vector<Bytes> messages,std::uint8_t next) {
        validate_month_limit(active);
        // 同一共享对局锁内读取资金、持仓及产权；终局后不再接受股票交易。
        const auto property=world.property->asset_values(rules.asset_settlement->property_value);
        std::vector<RichonlineClassicAssets> assets;
        for(std::uint8_t slot=0;slot<active.size();++slot) {
            const auto funds=world.ledger->snapshot(slot).funds;
            if(!funds.deposit) throw CodecError("richonline_classic_asset_deposit_unknown");
            assets.push_back({funds.cash,*funds.deposit,world.stocks->market_value(slot),property.at(slot)});
        }
        // 这条4010使客户端在7CF780显示到期文本269；不接420F或新的4011。
        messages.push_back(encode_richonline_turn4010({board.game_server_id,static_cast<std::int8_t>(next),
            static_cast<std::int8_t>(round_anchor),0},rules.opaque_turn7));
        phase=Phase::settling;collision_pending=false;movement.reset();pending_opcode.reset();
        append(messages,terminal->finish_month_limit(active,assets,rules.asset_settlement->evidence));
        return messages;
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
    bool payment_suppressed(const RichonlineClassicPropertyState& property) const {
        if(!property.owner || *property.owner>=statuses.size() || *property.owner==actor)
            throw CodecError("richonline_classic_rent_owner_invalid");
        const auto owner=*property.owner;
        const auto& owner_raw=raw->actor(owner);
        const auto& owner_status=statuses[owner];
        if(!owner_raw.hotel1493 || !owner_raw.hospital1494 || !owner_raw.jail1495 ||
            !owner_raw.kidnapped1497 || !owner_status.possession || !statuses[actor].possession)
            throw CodecError("richonline_classic_rent_state_unknown");
        // 7C94xx读取地主的状态，而1472/1480关系由付款者按地主索引读取。
        // 关系卡尚未开放；查封读取落脚地产，涨价在报价内逐块处理，不排除其他查封地块的贡献。
        // 7E4140的联排报价本身不检查查封，7C6640在租金入口检查目标D+4。
        return property.sealed_days || owner_status.possession==7 || owner_status.sleepwalking || owner_status.frozen ||
            *owner_raw.hotel1493!=-1 || *owner_raw.hospital1494!=-1 ||
            *owner_raw.jail1495!=-1 || *owner_raw.kidnapped1497!=-1;
    }
    std::uint32_t monetary_scale() const {
        const auto initial_scale=startup.recipients.front().snapshot.monetary_scale;
        // 当前会话只从新局4004开始：首次先手回合不增日，此后每完整轮增日一次。
        // 正基准每30次增日加1；类型19和外部4004改系数尚无写入口。
        const auto scale=static_cast<std::uint64_t>(initial_scale)+(initial_scale ? completed_rounds/30U : 0U);
        if(scale>static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max()))
            throw CodecError("richonline_classic_rent_scale_unsupported");
        return static_cast<std::uint32_t>(scale);
    }
    std::vector<Bytes> property_payment(const RichonlineClassicPropertyState& property,
        const std::optional<RichonlineClassicTradeResult>& trade_result={}) {
        const bool hotel=trade_result && property.kind==4;
        const auto suppressed=payment_suppressed(property);
        const auto owner=*property.owner;
        const auto possession=*statuses[actor].possession;
        const auto quote=trade_result ? trade_result->quote : suppressed || possession==0 ? 0 :
            property.kind==5 ? richonline_classic_computer_quote(property,monetary_scale(),rules.script) :
            world.property->rent_quote(property.id,monetary_scale());
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
            return begin_rent_transfer(property,static_cast<std::uint32_t>(amount),inventory,payer,payee,
                trade_result ? trade_result->message : stop(),trade_result ?
                    (hotel ? RichonlineRentTransferKind::hotel : RichonlineRentTransferKind::trade) : RichonlineRentTransferKind::rent);
        const bool bankrupt=std::string_view(outcome)=="bankrupt";
        auto hotel_entry=hotel && !bankrupt ? prepare_hotel_entry() : std::optional<PreparedHotelEntry>{};
        std::optional<PreparedRetirement> retirement;
        if(bankrupt) retirement=prepare_bankruptcy(actor);
        const auto charged=bankrupt ? payer.funds.cash+*payer.funds.deposit :
            std::string_view(outcome)=="paid" ? static_cast<std::uint32_t>(amount) : 0U;
        auto payer_after=payer.funds,payee_after=payee.funds;
        if(charged>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max())-*payee_after.deposit)
            throw CodecError("richonline_classic_rent_recipient_overflow");
        const auto cash_paid=std::min(charged,payer_after.cash);
        payer_after.cash-=cash_paid;*payer_after.deposit-=charged-cash_paid;*payee_after.deposit+=charged;
        auto messages=std::vector<Bytes>{trade_result ? trade_result->message : stop()};
        if(bankrupt && std::ranges::count(active,std::uint8_t{1})>2)
            messages.push_back(richonline_eliminate_actor(board.game_server_id,static_cast<std::int8_t>(actor)));
        const std::array updates{RichonlineGameFundsUpdate{actor,payer,payer_after},
            RichonlineGameFundsUpdate{owner,payee,payee_after}};
        if(!world.ledger->commit_batch(updates,[&]() {
            if(world.cards[actor]->inventory()!=inventory || world.property->snapshot(property.id)!=property) return false;
            if(hotel_entry && !raw->matches_hotel_entry(hotel_entry->raw)) return false;
            if(retirement && !commit_retirement(*retirement)) return false;
            if(retirement) retire_actor(actor);
            if(free_card) world.cards[actor]->commit_inventory(free_card->remaining_inventory);
            if(hotel_entry && !commit_hotel_entry(*hotel_entry)) std::terminate();
            return true;
        })) throw CodecError("richonline_classic_rent_commit_stale");
        if(bankrupt && std::ranges::count(active,std::uint8_t{1})==1)
            return finish_last_survivor(std::move(messages),actor);
        // 4013或4027已触发客户端6060/6061；只镜像账本/手牌，不发第二笔扣款或扣卡包。
        if(rules.log) rules.log(std::string(hotel ? "richonline_classic_hotel_payment actor=" :
            trade_result ? "richonline_classic_trade_payment actor=" :
            property.kind==5 ? "richonline_classic_computer_payment actor=" :
            "richonline_classic_rent actor=")+std::to_string(actor)+
            " owner="+std::to_string(owner)+" property="+std::to_string(property.id)+
            " sequence="+std::to_string(sequence)+" charged="+std::to_string(charged)+" outcome="+outcome);
        if(bankrupt) {collision_pending=false;return advance(std::move(messages));}
        if(hotel) return hotel_payment_complete(std::move(messages));
        return property_effects(std::move(messages));
    }
    std::vector<Bytes> begin_trade(const RichonlineClassicPropertyState& property) {
        const bool hotel=property.kind==4;
        if((hotel ? !rules.hotel : !rules.trade_result) || trade ||
            (property.kind!=3 && !hotel) || property.sprite_type!=12)
            throw CodecError("richonline_classic_trade_policy_missing");
        if(payment_suppressed(property)) return property_effects({stop()});
        // 在客户端开转盘前核实入住几何/状态，不能先收费再发现没有可恢复的道路。
        if(hotel) static_cast<void>(prepare_hotel_entry());
        // 地主的控制/收容状态阻止收费；付款人梦游或冰冻并不跳过他人的贸易中心。
        // 财神免付仍要经过转盘，不能在4013后直接换人让UI15悬空。
        auto packet=stop();
        trade=PendingTrade{property_entry(),property,statuses[*property.owner],raw->actor(*property.owner),
            rules.now()+rules.decision_timeout};
        phase=Phase::trade;pending_opcode=hotel ? 0x26 : 0x25;
        return {std::move(packet)};
    }
    bool trade_matches() const {
        return trade && property_entry()==trade->entry &&
            world.property->snapshot(trade->property.id)==trade->property &&
            statuses[*trade->property.owner]==trade->owner_status &&
            raw->actor(*trade->property.owner)==trade->owner_raw && active[*trade->property.owner];
    }
    std::vector<Bytes> finish_trade(bool timed_out) {
        if(phase!=Phase::trade || !trade_matches())
            throw CodecError("richonline_classic_trade_pending_stale");
        // 股票可在UI15等待时正常成交；用此刻余额计费。策略回调本身必须完全只读。
        std::vector<RichonlineGameFundsSnapshot> funds;
        std::vector<RichonlineChanceInventory> cards;
        for(std::uint8_t slot=0;slot<active.size();++slot) {
            funds.push_back(world.ledger->snapshot(slot));cards.push_back(world.cards[slot]->inventory());
        }
        const bool hotel=trade->property.kind==4;
        const auto selected=timed_out ? std::int8_t{-1} : hotel ? rules.hotel->result(context(),trade->property) :
            rules.trade_result(context(),trade->property);
        if((!timed_out && (selected<1 || selected>6)) || !trade_matches())
            throw CodecError("richonline_classic_trade_selection_invalid");
        for(std::uint8_t slot=0;slot<active.size();++slot)
            if(funds[slot]!=world.ledger->snapshot(slot) || cards[slot]!=world.cards[slot]->inventory())
                throw CodecError("richonline_classic_trade_selection_mutated_state");
        auto result=(hotel ? prepare_richonline_classic_hotel : prepare_richonline_classic_trade)(board.game_server_id,trade->property,
            monetary_scale(),selected,rules.script);
        const auto property=trade->property;
        auto& history=hotel ? retired_hotels : retired_trades;
        history.emplace_back(actor,calendar);
        if(history.size()>64) history.pop_front();
        pending_opcode.reset();
        // 4027/4028(-1)直接排6084。正常贸易经6042转附加效果，饭店经6043转6066入住。
        // 后继包在结果之后排队，客户端自身的3600ms暂停同时约束其消费顺序。
        auto messages=timed_out ? property_effects({std::move(result.message)}) : property_payment(property,result);
        trade.reset();
        if(rules.log) rules.log(std::string(hotel ? "richonline_classic_hotel property=" :
            "richonline_classic_trade property=")+std::to_string(property.id)+
            " result="+std::to_string(selected)+" quote="+std::to_string(result.quote)+
            " timed_out="+std::to_string(timed_out));
        return messages;
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
        const bool jail_news=richonline_classic_jail_news(event.opcode);
        if(jail_news || event.opcode==0x407f || event.opcode==0x4087) {
            const auto* policy=jail_news ? (rules.jail ? static_cast<const RichonlineClassicConfinementPolicy*>(&*rules.jail) : nullptr) :
                (rules.hospital ? &*rules.hospital : nullptr);
            if(!policy) throw CodecError("richonline_classic_confinement_policy_missing");
            const bool pardon_eligible=jail_news && rules.card_resources->automatic_card_eligible(startup.map_name,1057);
            const bool has_pardon=pardon_eligible && std::ranges::any_of(inventory_before,
                [](const auto& slot){return slot.card_id==1057;});
            const bool secondary_pardon_absent=!pardon_eligible || has_pardon ||
                (rules.jail->secondary_pardon_absent && rules.jail->secondary_pardon_absent(actor));
            // 免罪成功不查询/消费保险；其余分支只有第一套无卡时才要求第二套库存证明。
            const bool needs_secondary=!has_pardon && rules.card_resources->automatic_card_eligible(startup.map_name,1049) &&
                std::ranges::none_of(inventory_before,[](const auto& slot){return slot.card_id==1049;});
            const bool secondary_absent=!needs_secondary || (policy->secondary_insurance_absent &&
                policy->secondary_insurance_absent(actor));
            auto plan=jail_news ? prepare_richonline_classic_jail_news(board.game_server_id,current.landing,event,
                rain_before[actor].raw,before,inventory_before,*rules.card_resources,startup.map_name,
                secondary_pardon_absent,secondary_absent,rules.script) :
                prepare_richonline_classic_hospital_news(board.game_server_id,current.landing,event,
                rain_before[actor].raw,before,inventory_before,*rules.card_resources,startup.map_name,
                secondary_absent,rules.script);
            const bool pardoned=plan.pardon_slot>=0;
            const auto& pair=jail_news ? startup.topology.jail_positions() : startup.topology.hospital_positions();
            if(!pardoned && !pair) throw CodecError("richonline_classic_confinement_positions_missing");
            const auto entry=pardoned ? current.landing.position : (*pair)[0];
            const auto deadline=rules.now()+policy->entry_delay;
            const auto detail="richonline_classic_confinement_news actor="+std::to_string(actor)+
                " sequence="+std::to_string(sequence)+" days="+std::to_string(plan.days)+
                " jail="+std::to_string(jail_news)+" pardon_slot="+std::to_string(plan.pardon_slot)+
                " insurance_slot="+std::to_string(plan.insurance_slot)+
                " compensation="+std::to_string(plan.compensation);
            const std::array updates{plan.funds};
            if(!world.ledger->commit_batch(updates,[&]() {
                if(active!=active_before || raw->actor(actor)!=plan.raw_before || statuses[actor]!=plan.before ||
                    board.participants[actor].position!=current.landing.position ||
                    world.cards[actor]->inventory()!=plan.inventory_before) return false;
                if(!pardoned) {
                    if(jail_news) raw->enter_jail(actor,static_cast<std::int8_t>(plan.days));
                    else raw->enter_hospital(actor,static_cast<std::int8_t>(plan.days));
                }
                statuses[actor]=plan.after;board.participants[actor].position=entry;
                world.cards[actor]->commit_inventory(plan.inventory_after);return true;
            })) throw CodecError("richonline_classic_news_commit_stale");
            if(rules.log) rules.log(detail);
            // 免罪原消息已排stage2；保留原位置/状态，继续同格碰撞和岔路，不跳过落点。
            if(pardoned) return complete(std::move(plan.messages));
            confinement=jail_news ? Confinement::jail : Confinement::hospital;
            collision_pending=false;movement.reset();route={};route_cursor=0;
            pending_opcode.reset();phase=Phase::confinement_wait;confinement_deadline=deadline;
            // 原消息自己排动画9/11和可选保险，不再发加现金、扣卡或阶段2落点消息。
            return std::move(plan.messages);
        }
        if(event.opcode==0x4081) {
            if(!rules.kidnap) throw CodecError("richonline_classic_kidnap_policy_missing");
            auto plan=prepare_richonline_classic_kidnap_news(board.game_server_id,current.landing,event,
                rain_before[actor].raw,rules.script);
            const auto deadline=rules.now()+rules.kidnap->entry_delay;
            const auto detail="richonline_classic_kidnap_news actor="+std::to_string(actor)+
                " sequence="+std::to_string(sequence)+" days="+std::to_string(plan.days);
            if(active!=active_before || raw->actor(actor)!=plan.raw_before || statuses[actor]!=plan.before ||
                board.participants[actor].position!=current.landing.position)
                throw CodecError("richonline_classic_news_commit_stale");
            raw->enter_kidnapped(actor,static_cast<std::int8_t>(plan.days));statuses[actor]=plan.after;
            collision_pending=false;movement.reset();route={};route_cursor=0;
            pending_opcode.reset();phase=Phase::kidnap_wait;kidnap_deadline=deadline;
            if(rules.log) rules.log(detail);
            // 4081无stage2/0015回报：本次落点已结束，不再执行同格抢卡或岔路。
            return std::move(plan.messages);
        }
        if(event.days) throw CodecError("richonline_classic_news_parameters_invalid");
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
        // 受控/脚本跳过传送时，有地产仍进入原phase2，不能直接跳过租金及附加效果。
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
    std::optional<std::vector<Bytes>> local_reward_landing(const RichonlineLandingContext& landing) {
        const bool tickets=landing.static_type>=5 && landing.static_type<=7;
        if(!tickets && landing.static_type!=57) return {};
        // 这些格由客户端4013后的静态分派本地改钱；服务器只记同一笔账，不追加增量包。
        // 混合地产格仍未证明完整续接，不能完成静态格后直接越过其phase2。
        if(landing.property_ref!=-1) throw CodecError("richonline_classic_reward_property_unimplemented");
        const auto scripted=raw->game().scripted_event83830;
        if(!scripted || *scripted!=-1) throw CodecError("richonline_classic_reward_scripted_unavailable");
        const auto before=world.ledger->snapshot(actor);
        std::optional<RichonlineTicketLandingPlan> ticket_plan;
        std::optional<RichonlinePreparedSpecialLanding> merchant_plan;
        if(tickets) ticket_plan=prepare_richonline_ticket_landing(board.game_server_id,landing,before);
        else merchant_plan=prepare_richonline_special_landing(board.game_server_id,{landing,false},before);
        if(!ticket_plan && !merchant_plan) throw CodecError("richonline_classic_reward_plan_missing");
        const auto& after=ticket_plan ? ticket_plan->funds.after : merchant_plan->after();
        auto messages=ticket_plan ? ticket_plan->result.messages : merchant_plan->messages();
        if(rules.script) {
            bool prepared=false;
            const LuaBindings api{{"tile.tickets.prepare",[&](const LuaValue& args) {
                if(prepared || !ticket_plan) throw CodecError("lua_classic_ticket_out_of_scope");
                const auto& amount=args.at("amount");
                if(!amount.is_number_integer() || amount!=after.tickets-before.funds.tickets)
                    throw CodecError("lua_classic_ticket_amount_mismatch");
                prepared=true;return LuaValue(true);
            }},{"tile.merchant.prepare",[&](const LuaValue&) {
                if(prepared || !merchant_plan) throw CodecError("lua_classic_merchant_out_of_scope");
                prepared=true;return LuaValue{{"tickets",before.funds.tickets},{"scripted",false}};
            }}};
            const auto response=rules.script->call("tile.land",{{"type",landing.static_type},
                {"position",landing.position},{"actor",actor},{"map",startup.map_name},{"game_id",board.game_server_id},
                {"ticket_landing_available",tickets},{"merchant_landing_available",!tickets},
                {"synthetic_actor",false},{"controlled",richonline_landing_controlled(landing.actor_status)}},api);
            if(!prepared) throw CodecError("lua_classic_reward_prepare_required");
            if(merchant_plan) {
                if(!response.is_object() || response.size()!=3 || !response.contains("cash_credit") ||
                    !response.contains("ticket_cost") || !response.contains("messages"))
                    throw CodecError("lua_classic_merchant_response_invalid");
                const auto& credit=response.at("cash_credit");const auto& cost=response.at("ticket_cost");
                if(!credit.is_number_integer() || !cost.is_number_integer() ||
                    credit!=after.cash-before.funds.cash || cost!=before.funds.tickets-after.tickets)
                    throw CodecError("lua_classic_merchant_amount_mismatch");
            }
            const auto& packets=ticket_plan ? response : response.at("messages");
            if(!packets.is_array() || packets.size()!=messages.size())
                throw CodecError("lua_classic_reward_response_invalid");
            for(std::size_t index=0;index<messages.size();++index)
                if(lua_bytes(packets[index])!=messages[index])
                    throw CodecError("lua_classic_reward_response_mismatch");
        }
        const auto diagnostic="richonline_classic_local_reward actor="+std::to_string(actor)+
            " type="+std::to_string(landing.static_type)+" position="+std::to_string(landing.position)+
            " tickets_before="+std::to_string(before.funds.tickets)+" tickets_after="+std::to_string(after.tickets)+
            " cash_before="+std::to_string(before.funds.cash)+" cash_after="+std::to_string(after.cash);
        const auto authorize=[&]() noexcept {
            return active[actor] && statuses[actor]==landing.actor_status && collision_pending &&
                board.participants[actor].position==landing.position && raw->game().scripted_event83830==scripted;
        };
        // 完整Lua输出先核对，账本提交再核资金版本与真实状态；原生路径使用同一个计划。
        if(ticket_plan) {
            const std::array updates{ticket_plan->funds};
            if(!world.ledger->commit_batch(updates,authorize)) throw CodecError("richonline_classic_reward_stale");
        } else if(!commit_richonline_special_landing(*world.ledger,*merchant_plan,statuses[actor],authorize))
            throw CodecError("richonline_classic_reward_stale");
        if(rules.log) rules.log(diagnostic);
        return complete(std::move(messages));
    }
    std::vector<Bytes> shop_result(RichonlineLandingResult result) {
        if(shops.empty() || !collision_pending || result.status_change || result.temple_change)
            throw CodecError("richonline_classic_shop_result_invalid");
        if(result.progress==RichonlineLandingProgress::await_event && result.pending_opcode==0x30 && shops[actor]->active()) {
            phase=Phase::shop;pending_opcode=0x30;return std::move(result.messages);
        }
        if(result.progress!=RichonlineLandingProgress::complete || result.pending_opcode || shops[actor]->active())
            throw CodecError("richonline_classic_shop_result_invalid");
        retired_shops.emplace_back(actor,calendar);
        if(retired_shops.size()>64) retired_shops.pop_front();
        pending_opcode.reset();return complete(std::move(result.messages));
    }
    std::optional<std::vector<Bytes>> shop_landing(const RichonlineLandingContext& landing) {
        if(shops.empty() || landing.static_type!=10) return {};
        const auto scripted=raw->game().scripted_event83830;
        if(!scripted || *scripted!=-1) throw CodecError("richonline_classic_shop_scripted_unavailable");
        auto& shop=*shops[actor];
        auto prepared=shop.prepare_landing(landing);
        if(!prepared) throw CodecError("richonline_classic_shop_landing_invalid");
        if(rules.script) {
            bool called=false;
            const LuaBindings api{{"tile.shop.prepare",[&](const LuaValue&) {
                if(called) throw CodecError("lua_classic_shop_prepare_repeated");
                called=true;auto offers=LuaValue::array();
                for(const auto& offer:prepared->offers()) offers.push_back({{"card",offer.card_id},{"count",offer.count}});
                return LuaValue{{"open",prepared->opens()},{"offers",std::move(offers)},{"opaque",prepared->opaque()}};
            }}};
            const auto response=rules.script->call("tile.land",{{"type",10},{"position",landing.position},
                {"actor",actor},{"map",startup.map_name},{"game_id",board.game_server_id},
                {"shop_landing_available",true},{"synthetic_actor",false},
                {"controlled",richonline_landing_controlled(landing.actor_status)}},api);
            const auto& messages=prepared->result().messages;
            if(!called || !response.is_array() || response.size()!=messages.size())
                throw CodecError("lua_classic_shop_response_invalid");
            for(std::size_t index=0;index<messages.size();++index)
                if(lua_bytes(response[index])!=messages[index]) throw CodecError("lua_classic_shop_response_mismatch");
        }
        if(!active[actor] || statuses[actor]!=landing.actor_status || !collision_pending ||
            board.participants[actor].position!=landing.position || raw->game().scripted_event83830!=scripted)
            throw CodecError("richonline_classic_shop_landing_stale");
        auto offers=LuaValue::array(),inventory=LuaValue::array();
        for(const auto& offer:prepared->offers()) offers.push_back({{"card",offer.card_id},{"count",offer.count}});
        for(const auto& slot:world.cards[actor]->inventory()) inventory.push_back({{"card",slot.card_id},{"count",slot.count}});
        const auto diagnostic="richonline_classic_shop_landed "+LuaValue{{"actor",actor},{"calendar",calendar},
            {"position",landing.position},{"open",prepared->opens()},{"tickets",prepared->points()},
            {"offers",std::move(offers)},{"inventory",std::move(inventory)}}.dump();
        auto result=shop.commit_landing(*prepared);
        if(rules.log) rules.log(diagnostic);
        return shop_result(std::move(result));
    }
    RichonlineLotteryEntry lottery_entry() const {
        if(!lottery || startup.topology.cell(board.participants[actor].position).static_type!=4 ||
            richonline_landing_controlled(statuses[actor]) || raw->game().scripted_event83830!=-1)
            throw CodecError("richonline_classic_lottery_landing_invalid");
        return {board.game_server_id,calendar,sequence,actor,board.participants[actor].position};
    }
    std::vector<Bytes> lottery_result(RichonlineLotteryPurchase result) {
        retired_lottery.emplace_back(actor,calendar);
        if(retired_lottery.size()>64) retired_lottery.pop_front();
        pending_opcode.reset();
        if(rules.log) rules.log("richonline_classic_lottery_purchase actor="+std::to_string(actor)+
            " number="+std::to_string(result.number)+" pool="+std::to_string(news_fines)+
            " timed_out="+std::to_string(result.timed_out)+" sequence="+std::to_string(sequence));
        // 402B排6080 stage2，静态彩票格之后仍须地产业务/phase6，不提前换人。
        return property_effects({std::move(result.message)});
    }
    std::vector<Bytes> land() {
        if(collision_pending) throw CodecError("richonline_classic_phase6_already_pending");
        static_cast<void>(collision_actors());
        collision_pending=true;
        const auto current=context();
        if(auto messages=portal_landing(current.landing)) return std::move(*messages);
        // 7C54B0在静态格分派之前统一排除梦游/睡神/冰冻；仍须执行地产phase2与同格phase6。
        const bool controlled=richonline_landing_controlled(statuses[actor]);
        if(!controlled && lottery && current.landing.static_type==4) {
            if(current.landing.property_ref!=-1) throw CodecError("richonline_classic_lottery_property_unsupported");
            const auto scripted=raw->game().scripted_event83830;
            if(!scripted) throw CodecError("richonline_classic_lottery_game_unknown");
            auto packet=stop();
            if(*scripted!=-1 || !lottery->can_buy(actor))
                return property_effects({std::move(packet)});
            lottery->begin(lottery_entry());phase=Phase::lottery;pending_opcode=0x29;
            return {std::move(packet)};
        }
        // 先完成静态/地产业务，同格效果由complete统一在phase6执行，不能提前抢卡。
        if(auto result=services.landing(current)) return accept_result(std::move(*result));
        if(!controlled) {
            if(auto messages=local_reward_landing(current.landing)) return std::move(*messages);
            if(auto messages=shop_landing(current.landing)) return std::move(*messages);
            if(current.landing.static_type==1 && rules.news) return money_news(current);
            if(current.landing.static_type==9) {
                if(current.landing.property_ref!=-1)
                    throw CodecError("richonline_classic_bank_property_unimplemented");
                auto messages=std::vector<Bytes>{stop()};
                append(messages,open_bank(RichonlineGameBankVisit::landing));return messages;
            }
        }
        if(current.landing.property_ref>=0) {
            const auto property=world.property->snapshot(current.landing.property_ref);
            if(property.kind!=0 && property.kind!=1 && !(property.sprite_type==12 && property.kind==-1) &&
                !(property.kind==2 && world.research) && !(property.kind==3 && rules.trade_result) &&
                !(property.kind==4 && rules.hotel) && property.kind!=5 &&
                !(property.sprite_type==12 && property.kind==6))
                throw CodecError("richonline_classic_property_landing_unimplemented");
            // 7C6640先执行自有加盖，再到LABEL_217升级询问；4021完成后排6084
            // 直接续地产附加效果。服务端仅在首次落点镜像，使用升级前公司等级。
            if(property.kind==6 && property.owner) {
                const bool suppressed=*property.owner==actor ? controlled || property.sealed_days :
                    payment_suppressed(property);
                if(!suppressed) apply_estate_effect(property.id);
            }
            if(property.owner && *property.owner!=actor && (property.kind==0 || property.kind==1 || property.kind==5))
                return property_payment(property);
            if(property.owner && *property.owner!=actor && (property.kind==3 || property.kind==4)) return begin_trade(property);
            // 大型空地、他人研究所不收住宅租金，仍保留附加效果及同格续行。
            if(property.owner && *property.owner!=actor) return property_effects({stop()});
            const bool purchase=!property.owner;
            auto entry=property_entry();
            if(property.kind==2 && property.owner==actor && !entry.sealed &&
                !richonline_landing_controlled(entry.status) && !world.research->registered(property.id,actor)) {
                auto packet=stop();
                world.research->begin(entry);phase=Phase::research;pending_opcode=0x24;
                return {std::move(packet)};
            }
            std::uint32_t cost=purchase ? property.price : property.sprite_type==11 ? 500U : 1500U;
            if(entry.land_equipment>0) cost/=2;
            const bool eligible=!controlled && (purchase || (!entry.sealed && property.kind!=1 && property.level<5));
            if(eligible && world.ledger->snapshot(actor).funds.cash>cost) {
                auto packet=stop();
                pending_opcode=world.property->begin(purchase ? RichonlineClassicPropertyChoice::purchase :
                    RichonlineClassicPropertyChoice::upgrade,entry);
                phase=Phase::property;return {std::move(packet)};
            }
            return property_effects({stop()});
        }
        if(controlled) return complete({stop()});
        if(auto prepared=world.cards[actor]->prepare_landing(current.landing)) {
            auto result=std::move(prepared->result);
            world.cards[actor]->commit_landing(*prepared);
            return accept_result(std::move(result));
        }
        if(current.landing.static_type!=-1)
            throw CodecError("richonline_classic_static_landing_unimplemented");
        return complete({stop()});
    }
    std::vector<Bytes> property_result(RichonlineClassicPropertyResult result) {
        if(result.continuation==RichonlineClassicPropertyContinuation::building_choice) {
            if(!world.property->active()) throw CodecError("richonline_classic_building_wait_missing");
            pending_opcode=0x23;return {std::move(result.message)};
        }
        if(world.property->active()) throw CodecError("richonline_classic_property_wait_remaining");
        pending_opcode.reset();return property_effects({std::move(result.message)});
    }
    std::vector<Bytes> research_result(RichonlineClassicResearchResult result) {
        const auto property=world.property->snapshot(result.entry.property);
        retired_research.emplace_back(actor,calendar);
        if(retired_research.size()>64) retired_research.pop_front();
        auto messages=std::vector<Bytes>{std::move(result.message)};
        const auto entry=property_entry();
        if(entry!=result.entry) throw CodecError("richonline_classic_research_continuation_stale");
        if(rules.log) rules.log("richonline_classic_research_choice actor="+std::to_string(actor)+
            " property="+std::to_string(entry.property)+" choice="+std::to_string(result.choice)+
            " registered_slot="+(result.registered_slot ? std::to_string(*result.registered_slot) : "-1")+
            " timed_out="+std::to_string(result.timed_out));
        auto cost=property.sprite_type==11 ? 500U : 1500U;
        if(entry.land_equipment>0) cost/=2;
        // 4026自身重入stage2/selector3，先询问升级，不重新打开UI14或重发4013。
        if(property.level<5 && world.ledger->snapshot(actor).funds.cash>cost) {
            pending_opcode=world.property->begin(RichonlineClassicPropertyChoice::upgrade,entry);
            phase=Phase::property;return messages;
        }
        pending_opcode.reset();return property_effects(std::move(messages));
    }
    struct PreparedMove { RichonlineRoute route;Bytes packet;RichonlineSharedMovementWait wait; };
    PreparedMove prepare_move(std::optional<std::uint8_t> selected={},std::int32_t charge=0,
        std::optional<std::uint8_t> count_override={},std::optional<std::array<std::int8_t,3>> previous_faces={}) {
        const auto forced=statuses[actor].one_step || statuses[actor].turtle ? std::optional<std::uint8_t>{1} :
            statuses[actor].six_steps ? std::optional<std::uint8_t>{6} : std::nullopt;
        // 沿用既有遥控卡政策：卡片指定覆盖本次固定步数，不清除持续状态；金豆骰另行拒绝。
        const auto chosen=selected ? selected : forced;
        const auto count=chosen ? std::uint8_t{1} : count_override.value_or(dice[actor]);
        if(count<1 || count>3 || charge<0) throw CodecError("richonline_classic_move_policy_invalid");
        std::array<std::int8_t,3> faces{1,rules.inactive_ui_dice[0],rules.inactive_ui_dice[1]};
        std::int32_t budget=0;
        for(std::uint8_t index=0;index<count;++index) {
            const auto choice=chosen ? static_cast<std::size_t>(*chosen-1U) : previous_faces ?
                static_cast<std::size_t>((*previous_faces)[index]-1) : rules.random(6);
            if(choice>=6) throw CodecError("richonline_classic_die_invalid");
            faces[index]=static_cast<std::int8_t>(choice+1);budget+=faces[index];
        }
        const auto& person=board.participants[actor];
        auto proposed=build_richonline_route(startup.topology,
            {person.position,person.direction,budget,{},!confinement_controlled(),
                static_cast<bool>(bank) || confinement_controlled()},rules.random);
        // 最后一步仍停在入口，等0011全员汇合才传送；途中61由不可变路线处理。
        std::vector<RichonlineMoveDirection> directions;
        for(const auto direction:proposed.directions) directions.push_back(static_cast<RichonlineMoveDirection>(direction));
        auto wire=rules.route_wire;wire.local_reserve_charge=charge;
        auto packet=encode_richonline_route4011({board.game_server_id,person.position,count,faces,
            std::move(directions),proposed.landings.size()},wire);
        if(movement_sequence==std::numeric_limits<std::uint64_t>::max())
            throw CodecError("richonline_classic_movement_sequence_overflow");
        static_cast<void>(raw->actor(actor));
        std::optional<std::size_t> checkpoint;
        if(bank && !confinement_controlled()) for(std::size_t index=0;index+1<proposed.landings.size();++index)
            if(startup.topology.cell(proposed.landings[index]).static_type==9) {checkpoint=index;break;}
        const RichonlineSharedMovementWait wait{movement_sequence+1,calendar,
            proposed.landings.at(checkpoint.value_or(proposed.landings.size()-1)),actor,
            static_cast<std::uint16_t>(checkpoint ? 0x28 : 0x11)};
        return {std::move(proposed),std::move(packet),wait};
    }
    static bool payment_committed(const RichonlinePaymentResult& paid) {
        switch(paid.status) {
        case RichonlinePaymentStatus::committed:return true;
        case RichonlinePaymentStatus::account_refused:
        case RichonlinePaymentStatus::insufficient_reserve:return false;
        case RichonlinePaymentStatus::duplicate:
        case RichonlinePaymentStatus::recovery_required:
            throw CodecError("richonline_classic_payment_recovery_required");
        }
        throw CodecError("richonline_classic_payment_result_invalid");
    }
    std::string payment_operation(const char* kind,std::uint8_t value) const {
        return rules.payment->actors[actor].operation_prefix+":turn="+std::to_string(sequence)+
            ":counter="+std::to_string(calendar)+":"+kind+":"+std::to_string(value);
    }
    template<class Pay>
    std::optional<std::vector<Bytes>> pay_and_move(PreparedMove& move,View request,Pay&& pay) {
        // 先分配响应和迟到请求记录；扣费成功后只提交已经验证的移动状态。
        std::vector<Bytes> messages{move.packet};
        if(!request.empty()) retired.push_back({actor,Bytes(request.begin(),request.end())});
        bool accepted=false;
        try {accepted=pay();} catch(...) {if(!request.empty())retired.pop_back();throw;}
        if(!accepted) {if(!request.empty())retired.pop_back();return {};}
        if(retired.size()>64) retired.pop_front();
        commit_move(std::move(move));return std::optional{std::move(messages)};
    }
    std::vector<Bytes> random_move(View request) {
        const bool automatic=confinement_controlled();
        const auto forced=statuses[actor].one_step || statuses[actor].six_steps || statuses[actor].turtle;
        auto count=forced ? std::uint8_t{1} : dice[actor];
        std::vector<Bytes> refused{encode_richonline_dice_recovery400b(board.game_server_id)};
        if(payments.empty()) {
            // 无绑定时只有一颗普通骰得到已证实的免费资格；不能把最大可选骰数当成免费额度。
            if(count>1 && !automatic)return refused;
            auto move=prepare_move({},0,1);
            return pay_and_move(move,request,[]{return true;}).value();
        }
        const auto& equipment=payment_equipment[actor];
        auto& payment=*payments[actor];
        if(automatic) while(count>1 && static_cast<std::uint32_t>(payment.quote_random_dice(count,equipment))>payment.reserve()) --count;
        const auto cost=payment.quote_random_dice(count,equipment);
        auto move=prepare_move({},cost,count);
        const auto operation=payment_operation("random-dice",count);
        if(auto messages=pay_and_move(move,request,[&] {
            return cost==0 || payment_committed(payment.random_dice(operation,count,equipment));
        })) return std::move(*messages);
        if(!automatic)return refused;
        // 自动掷骰被账号拒付时按载具免费额度继续，复用已抽骰面，不再次抽取有利结果。
        const auto free_count=equipment.dice_vehicle==RichonlineDiceVehicle::car ? 3U :
            equipment.dice_vehicle==RichonlineDiceVehicle::motorcycle ? 2U : 1U;
        auto fallback=prepare_move({},0,static_cast<std::uint8_t>(std::min<unsigned>(count,free_count)),
            std::array<std::int8_t,3>{static_cast<std::int8_t>(move.packet[8]),static_cast<std::int8_t>(move.packet[9]),
                static_cast<std::int8_t>(move.packet[10])});
        return pay_and_move(fallback,request,[]{return true;}).value();
    }
    std::vector<Bytes> paid_move(View request) {
        const auto choice=std::get<RichonlinePaidDiceRequest22>(parse_richonline_controlled_dice_request(request));
        std::vector<Bytes> refused{encode_richonline_dice_recovery400b(board.game_server_id)};
        if(payments.empty() || richonline_landing_controlled(statuses[actor]) || statuses[actor].one_step ||
            statuses[actor].six_steps || statuses[actor].turtle || statuses[actor].stay) return refused;
        auto& payment=*payments[actor];const auto& equipment=payment_equipment[actor];
        const auto cost=payment.quote_paid_die(choice.selected_die,equipment);
        auto move=prepare_move(choice.selected_die,cost);
        const auto operation=payment_operation("paid-die",choice.selected_die);
        if(auto messages=pay_and_move(move,request,[&] {
            return payment_committed(payment.paid_die(operation,choice.selected_die,equipment));
        })) return std::move(*messages);
        return refused;
    }
    void commit_move(PreparedMove move) noexcept {
        route=std::move(move.route);
        raw->apply_s2c4011_movement(actor);
        route_cursor=0;movement_sequence=move.wait.sequence;movement=move.wait;
        phase=Phase::moving;
    }
    std::vector<Bytes> immediate_move_card(View request) {
        const auto opcode=read_le(request.first(2));
        const auto owner=world.cards[actor];
        const auto before_actor=actor;
        const auto before_calendar=calendar;
        const auto before_sequence=sequence;
        const auto before_movement=movement_sequence;
        const auto before_position=board.participants[actor].position;
        const auto before_heading=board.participants[actor].direction;
        const auto before_status=statuses[actor];
        const auto before_raw=raw->actor(actor);
        std::optional<RichonlineFixedStepCardPlan> card;
        std::optional<PreparedMove> move;
        std::vector<Bytes> messages;
        try {
            if(phase!=Phase::roll || !active[actor] || owner->actor_slot()!=actor ||
                owner->game_id()!=board.game_server_id || owner->game_mode()!=0 ||
                richonline_landing_controlled(before_status) || before_status.stay ||
                raw->game().scripted_event83830!=-1 || before_raw.hotel1493!=-1 ||
                before_raw.hospital1494!=-1 || before_raw.jail1495!=-1 || before_raw.kidnapped1497!=-1)
                throw CodecError("richonline_classic_move_card_unavailable");
            if(opcode==103) {
                const auto use=std::get<RichonlineCardDiceRequest103>(parse_richonline_controlled_dice_request(request));
                if(use.calendar_counter!=calendar) throw CodecError("richonline_classic_move_card_calendar_mismatch");
                const auto consumed=owner->prepare_consumption(use.inventory_slot,1038);
                if(!consumed) throw CodecError("richonline_classic_move_card_not_owned");
                card=RichonlineFixedStepCardPlan{encode_richonline_card_used40b7(
                    {board.game_server_id,use.inventory_slot,use.inventory_bank}),*consumed,use.selected_die};
            } else {
                card=plan_richonline_fixed_step_card(board.game_server_id,
                    parse_richonline_fixed_step_card(request),calendar,*owner);
            }
            if(rules.script) {
                bool consumed=false,routed=false,invalid_call=false;
                // 只开放两个准备接口。脚本不能调用旧game.native、数据库或其他状态写接口。
                const LuaBindings bindings{
                    {"card.prepare",[&](const LuaValue& args) {
                        if(consumed || routed || args!=LuaValue{{"card",card->consumption.card_id}} ||
                            !args.at("card").is_number_integer()) {
                            invalid_call=true;
                            throw CodecError("lua_classic_move_card_consumption_invalid");
                        }
                        consumed=true;
                        return LuaValue{{"slot",card->consumption.slot},{"bank",0}};
                    }},
                    {"route.prepare_move",[&](const LuaValue& args) {
                        if(!consumed || routed || args!=LuaValue{{"steps",card->steps}} ||
                            !args.at("steps").is_number_integer()) {
                            invalid_call=true;
                            throw CodecError("lua_classic_move_card_steps_invalid");
                        }
                        routed=true;move=prepare_move(card->steps);
                        return LuaValue::array({lua_bytes(View(move->packet))});
                    }}
                };
                const auto result=rules.script->call("game.action",{{"payload",lua_bytes(request)},
                    {"opcode",opcode},{"map",startup.map_name},{"actor",actor},
                    {"calendar",calendar},{"game_id",board.game_server_id}},bindings);
                if(invalid_call || !consumed || !routed || !move || !result.is_array() || result.size()!=2 ||
                    !result[0].is_string() || !result[1].is_string() ||
                    lua_bytes(result[0])!=card->confirmation || lua_bytes(result[1])!=move->packet)
                    throw CodecError("lua_classic_move_card_response_invalid");
            } else move=prepare_move(card->steps);
            // 始终先确认扣卡，再广播同一条4011。准备途中失败不能只扣卡而没有移动。
            messages={card->confirmation,move->packet};
        } catch(const std::exception& error) {
            if(rules.log) rules.log("richonline_classic_move_card_refused actor="+std::to_string(actor)+
                " opcode="+std::to_string(opcode)+" reason="+error.what());
            return {encode_richonline_dice_recovery400b(board.game_server_id)};
        }
        if(phase!=Phase::roll || actor!=before_actor || calendar!=before_calendar || sequence!=before_sequence ||
            movement_sequence!=before_movement || !active[actor] || world.cards[actor]!=owner ||
            owner->inventory()!=card->consumption.source_inventory || statuses[actor]!=before_status ||
            raw->actor(actor)!=before_raw || board.participants[actor].position!=before_position ||
            board.participants[actor].direction!=before_heading)
            throw CodecError("richonline_classic_move_card_stale");
        remember(actor,request);
        owner->commit_consumption(card->consumption);
        commit_move(std::move(*move));
        return messages;
    }
    std::vector<Bytes> motion_card(View request) {
        const auto opcode=read_le(request.first(2));
        const auto source=world.cards[actor];
        const auto source_actor=actor;
        const auto source_calendar=calendar;
        const auto source_sequence=sequence;
        const auto source_movement=movement_sequence;
        const auto source_person=board.participants[actor];
        const auto source_status=statuses[actor];
        const auto source_raw=raw->actor(actor);
        const auto source_inventory=source->inventory();
        std::optional<RichonlineMotionCardPlan> card;
        std::optional<PreparedMove> next_move;
        std::optional<RichonlineSharedMovementWait> stationary_wait;
        RichonlineChanceInventory target_inventory_before{},target_inventory_after{};
        RichonlineBoardParticipant target_person{};
        RichonlineRawActorState target_raw{};
        std::shared_ptr<RichonlinePlayerCards> target_owner;
        std::uint8_t target=0;
        std::vector<Bytes> messages;
        try {
            if(!rules.motion_cards || phase!=Phase::roll || !active[actor] ||
                source->actor_slot()!=actor || source->game_id()!=board.game_server_id || source->game_mode()!=0 ||
                richonline_landing_controlled(source_status) || source_status.stay ||
                !raw->game().scripted_event83830 || *raw->game().scripted_event83830!=-1 ||
                !source_raw.hotel1493 || !source_raw.hospital1494 || !source_raw.jail1495 ||
                !source_raw.kidnapped1497 || *source_raw.hotel1493!=-1 ||
                *source_raw.hospital1494!=-1 || *source_raw.jail1495!=-1 ||
                *source_raw.kidnapped1497!=-1)
                throw CodecError("richonline_classic_motion_card_unavailable");
            const auto use=parse_richonline_motion_card(request);
            target=static_cast<std::uint8_t>(use.target_actor);
            if(target>=active.size()) throw CodecError("richonline_classic_motion_target_invalid");
            const auto& recipient=world.cards[target];
            if(!recipient || recipient->actor_slot()!=target || recipient->game_id()!=board.game_server_id ||
                recipient->game_mode()!=0)
                throw CodecError("richonline_classic_motion_inventory_owner_invalid");
            target_owner=recipient;
            target_person=board.participants[target];
            target_raw=raw->actor(target);
            target_inventory_before=recipient->inventory();
            const bool target_available=target_raw.hotel1493 && target_raw.hospital1494 &&
                target_raw.jail1495 && target_raw.kidnapped1497 && *target_raw.hotel1493==-1 &&
                *target_raw.hospital1494==-1 && *target_raw.jail1495==-1 && *target_raw.kidnapped1497==-1;
            const RichonlineMotionCardTarget before{use.target_actor,target_person.position,target_person.direction,
                statuses[target],active[target]!=0,target_available};
            card=plan_richonline_motion_card(board.game_server_id,use,calendar,
                static_cast<std::int8_t>(actor),before,*rules.motion_cards,startup.topology,
                rules.random,*source);
            target_inventory_after=target==actor ? card->consumption.remaining_inventory : target_inventory_before;
            if(use.kind==RichonlineMotionCard::sleep1042) {
                // 自动防梦游先查主手牌；第二套不可写时只能接受准入层的无卡证明。
                RichonlineProtectionInventory protection_inventory{target,target,target_inventory_after,
                    std::nullopt,false};
                const auto protection=resolve_richonline_sleep_protection(startup.map_name,
                    *rules.card_resources,protection_inventory,card->before.status);
                if(!protection.consumed && !card->before.status.protected_from_status &&
                    rules.card_resources->automatic_card_eligible(startup.map_name,1071) &&
                    (!rules.secondary_sleep_protection_absent ||
                    !rules.secondary_sleep_protection_absent(target)))
                    throw CodecError("richonline_classic_sleep_secondary_protection_unknown");
                target_inventory_after=protection.after.main;
                if(protection.consumed || card->before.status.protected_from_status) {
                    card->after.status=card->before.status;
                    card->blocked_by_protection=true;
                }
            }
            if(rules.script) {
                bool consumed=false,planned=false,invalid_call=false;
                const LuaBindings bindings{
                    {"card.prepare",[&](const LuaValue& args) {
                        if(consumed || planned || args!=LuaValue{{"card",card->consumption.card_id}} ||
                            !args.at("card").is_number_integer()) {
                            invalid_call=true;
                            throw CodecError("lua_classic_motion_consumption_invalid");
                        }
                        consumed=true;
                        return LuaValue{{"slot",card->consumption.slot},{"bank",0}};
                    }},
                    {"motion.prepare",[&](const LuaValue& args) {
                        if(!consumed || planned || args!=LuaValue{{"card",card->consumption.card_id},
                            {"target",target}} || !args.at("card").is_number_integer() ||
                            !args.at("target").is_number_integer()) {
                            invalid_call=true;
                            throw CodecError("lua_classic_motion_target_invalid");
                        }
                        planned=true;
                        if(card->movement_steps) next_move=prepare_move(*card->movement_steps);
                        auto movement=LuaValue::array(),recovery=LuaValue::array();
                        if(next_move) movement.push_back(lua_bytes(View(next_move->packet)));
                        if(card->recovery) recovery.push_back(lua_bytes(View(*card->recovery)));
                        return LuaValue{{"response",lua_bytes(View(card->response))},
                            {"movement",std::move(movement)},{"recovery",std::move(recovery)},
                            {"continuation",card->continuation==RichonlineMotionCardContinuation::await_same_position17 ?
                                "stationary" : "resume"}};
                    }}
                };
                const auto result=rules.script->call("game.action",{{"payload",lua_bytes(request)},
                    {"opcode",opcode},{"map",startup.map_name},{"actor",actor},
                    {"calendar",calendar},{"game_id",board.game_server_id}},bindings);
                messages.push_back(card->response);
                if(next_move) messages.push_back(next_move->packet);
                if(card->recovery) messages.push_back(*card->recovery);
                if(invalid_call || !consumed || !planned ||
                    card->movement_steps.has_value()!=next_move.has_value() || !result.is_array() ||
                    result.size()!=messages.size())
                    throw CodecError("lua_classic_motion_response_invalid");
                for(std::size_t index=0;index<messages.size();++index)
                    if(!result[index].is_string() || lua_bytes(result[index])!=messages[index])
                        throw CodecError("lua_classic_motion_response_invalid");
            } else {
                if(card->movement_steps) next_move=prepare_move(*card->movement_steps);
                messages.push_back(card->response);
                if(next_move) messages.push_back(next_move->packet);
                if(card->recovery) messages.push_back(*card->recovery);
            }
            if(card->continuation==RichonlineMotionCardContinuation::await_same_position17) {
                if(movement_sequence==std::numeric_limits<std::uint64_t>::max())
                    throw CodecError("richonline_classic_movement_sequence_overflow");
                stationary_wait=RichonlineSharedMovementWait{movement_sequence+1,calendar,
                    source_person.position,actor,0x11};
            }
        } catch(const std::exception& error) {
            if(rules.log) rules.log("richonline_classic_motion_card_refused actor="+std::to_string(actor)+
                " opcode="+std::to_string(opcode)+" reason="+error.what());
            return {encode_richonline_dice_recovery400b(board.game_server_id)};
        }
        if(phase!=Phase::roll || actor!=source_actor || calendar!=source_calendar ||
            sequence!=source_sequence || movement_sequence!=source_movement || !active[actor] ||
            !active[target] || world.cards[actor]!=source ||
            source->inventory()!=source_inventory || world.cards[target]!=target_owner ||
            target_owner->inventory()!=target_inventory_before ||
            board.participants[actor].position!=source_person.position ||
            board.participants[actor].direction!=source_person.direction ||
            board.participants[target].position!=target_person.position ||
            board.participants[target].direction!=target_person.direction ||
            raw->actor(actor)!=source_raw || raw->actor(target)!=target_raw ||
            statuses[actor]!=source_status || statuses[target]!=card->before.status)
            throw CodecError("richonline_classic_motion_card_stale");
        remember(actor,request);
        if(target==actor) source->commit_inventory(target_inventory_after);
        else {
            source->commit_consumption(card->consumption);
            world.cards[target]->commit_inventory(target_inventory_after);
        }
        statuses[target]=card->after.status;
        board.participants[target].direction=card->after.heading;
        if(next_move) commit_move(std::move(*next_move));
        else if(stationary_wait) {
            route={};route_cursor=0;
            movement_sequence=stationary_wait->sequence;movement=*stationary_wait;
            phase=Phase::stationary;
        }
        if(rules.log) rules.log("richonline_classic_motion_card actor="+std::to_string(actor)+
            " target="+std::to_string(target)+" opcode="+std::to_string(opcode)+
            " blocked="+std::to_string(card->blocked_by_protection)+
            " moved="+std::to_string(next_move.has_value())+" sequence="+std::to_string(sequence));
        return messages;
    }
    std::optional<std::size_t> next_bank() const {
        // 最后一格使用0011和落点4013，只有尚未走完的中间格使用0028。
        if(!bank || confinement_controlled()) return {};
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
    std::vector<Bytes> theft_card(View request) {
        std::optional<RichonlineTheftPlan> plan;
        const auto before_actor=actor;
        const auto before_calendar=calendar;
        const auto before_sequence=sequence;
        std::uint8_t target=0;
        try {
            const auto use=decode_richonline_theft_request(request);
            target=use.target;
            if(use.calendar!=calendar || target>=active.size() || target==actor || !active[target] ||
                richonline_landing_controlled(statuses[actor]) || raw->game().scripted_event83830!=-1)
                throw CodecError("richonline_classic_theft_unavailable");
            const auto& source=raw->actor(actor);
            if(source.hotel1493!=-1 || source.hospital1494!=-1 || source.jail1495!=-1 || source.kidnapped1497!=-1)
                throw CodecError("richonline_classic_theft_actor_unavailable");
            const auto& victim=raw->actor(target);
            // 6552A0的64FF10选人守卫排除旅馆、医院、监狱和绑架；不额外排除冰冻目标。
            if(victim.hotel1493!=-1 || victim.hospital1494!=-1 || victim.jail1495!=-1 || victim.kidnapped1497!=-1)
                throw CodecError("richonline_classic_theft_target_unavailable");
            const bool needs_secondary=rules.card_resources->automatic_card_eligible(startup.map_name,1074) &&
                std::ranges::none_of(world.cards[target]->inventory(),[](const auto& slot){return slot.card_id==1074;});
            const bool secondary_absent=!needs_secondary || (rules.secondary_theft_protection_absent &&
                rules.secondary_theft_protection_absent(target));
            plan=prepare_richonline_theft(use,*world.cards[actor],*world.cards[target],
                *rules.card_resources,secondary_absent,rules.script);
        } catch(const CodecError& error) {
            if(rules.log) rules.log("richonline_classic_theft_refused actor="+std::to_string(actor)+" reason="+error.what());
            return {encode_richonline_dice_recovery400b(board.game_server_id)};
        }
        std::vector<Bytes> messages{plan->response()};
        if(phase!=Phase::roll || actor!=before_actor || calendar!=before_calendar || sequence!=before_sequence ||
            !active[actor] || !active[target]) throw CodecError("richonline_classic_theft_context_stale");
        remember(actor,request);
        if(!commit_richonline_theft(*world.cards[actor],*world.cards[target],*plan))
            throw CodecError("richonline_classic_theft_inventory_stale");
        if(rules.log) rules.log("richonline_classic_theft actor="+std::to_string(actor)+
            " target="+std::to_string(target)+" blocked="+std::to_string(plan->protected_by_card())+
            " card="+std::to_string(plan->transferred_card())+" sequence="+std::to_string(sequence));
        return messages;
    }
    RichonlineHibernateSnapshot hibernate_snapshot() const {
        RichonlineHibernateSnapshot snapshot{};
        snapshot.game_id=board.game_server_id;snapshot.calendar=calendar;
        snapshot.active_actor=static_cast<std::int8_t>(actor);snapshot.roll_phase=phase==Phase::roll;
        snapshot.active_actor_can_act=active[actor] && !richonline_landing_controlled(statuses[actor]) &&
            !statuses[actor].stay && raw->game().scripted_event83830==-1;
        for(std::uint8_t slot=0;slot<active.size();++slot) {
            const auto& owner=world.cards[slot];
            if(!owner || owner->actor_slot()!=slot || owner->game_id()!=board.game_server_id || owner->game_mode()!=0)
                throw CodecError("richonline_classic_hibernate_inventory_owner_invalid");
            auto& target=snapshot.actors[slot];
            target.present=active[slot];target.status=statuses[slot];
            target.inventory={slot,slot,owner->inventory(),std::nullopt,false};
            // 经典结盟入口尚未开放，关系保持开局全零，不能读取另一局或BOSS的关系。
            // 接入结盟时须将关系权威一并传入本快照及提交，而非继续使用此空关系前提。
            if(!target.present) continue;
            const auto& state=raw->actor(slot);
            if(!state.hotel1493 || !state.hospital1494 || !state.jail1495 || !state.kidnapped1497)
                throw CodecError("richonline_classic_hibernate_raw_unknown");
            target.raw1493=*state.hotel1493;target.raw1494=*state.hospital1494;
            target.raw1495=*state.jail1495;target.raw1497=*state.kidnapped1497;
        }
        return snapshot;
    }
    std::vector<Bytes> hibernate_card(View request) {
        // 164没有请求序号。同一回合相同槽位报文按重发处理，不能重复扣506/1071。
        if(request.size()==6 && request[4]<accepted_hibernate.size() && accepted_hibernate[request[4]] &&
            std::ranges::equal(request,*accepted_hibernate[request[4]])) return {};
        const auto before_sequence=sequence;
        const auto owners=world.cards;
        std::optional<RichonlineHibernatePlan> plan;
        std::array<std::uint8_t,6> accepted{};
        std::vector<Bytes> messages;
        try {
            if(!rules.hibernate) throw CodecError("richonline_classic_hibernate_rules_missing");
            const auto use=decode_richonline_hibernate164(request);
            const auto before=hibernate_snapshot();
            const auto consumption=owners[actor]->prepare_consumption(use.inventory_slot,506);
            if(!consumption) throw CodecError("richonline_classic_hibernate_not_owned");
            plan=plan_richonline_hibernate(use,board.game_server_id,static_cast<std::int8_t>(actor),
                startup.map_name,*rules.card_resources,*rules.hibernate,before);
            if(consumption->remaining_inventory!=plan->after.actors[actor].inventory.main)
                throw CodecError("richonline_classic_hibernate_consumption_mismatch");
            // 复用真实1071保护。主手牌未抵挡且地图允许时，必须证明第二套没有保护卡；
            // 未知不能当作无卡，否则会出现客户端抵挡、服务端却冻结的分歧。
            for(std::uint8_t slot=0;slot<active.size();++slot)
                if(plan->effects[slot]==RichonlineHibernateEffect::frozen &&
                    rules.card_resources->automatic_card_eligible(startup.map_name,1071) &&
                    (!rules.secondary_sleep_protection_absent || !rules.secondary_sleep_protection_absent(slot)))
                    throw CodecError("richonline_classic_hibernate_secondary_protection_unknown");
            if(rules.script) {
                bool consumed=false,snapshot_read=false,prepared=false,invalid=false;
                const auto reject=[&]() -> LuaValue {
                    invalid=true;throw CodecError("lua_classic_hibernate_plan_invalid");
                };
                const LuaBindings bindings{
                    {"card.prepare",[&](const LuaValue& args) {
                        if(consumed || args!=LuaValue{{"card",506}} || !args.at("card").is_number_integer())
                            return reject();
                        consumed=true;return LuaValue{{"slot",use.inventory_slot},{"bank",0}};
                    }},
                    {"hibernate.snapshot",[&](const LuaValue&) {
                        if(!consumed || snapshot_read) return reject();
                        snapshot_read=true;auto actors=LuaValue::array();
                        for(std::size_t slot=0;slot<before.actors.size();++slot) {
                            const auto& target=before.actors[slot];
                            actors.push_back({{"slot",slot},{"present",target.present},{"hotel",target.raw1493},
                                {"hospital",target.raw1494},{"jail",target.raw1495},{"kidnapped",target.raw1497},
                                {"frozen",target.status.frozen}});
                        }
                        return LuaValue{{"actor",actor},{"actors",std::move(actors)},
                            {"frozen_turns",rules.hibernate->frozen_turns}};
                    }},
                    {"hibernate.prepare",[&](const LuaValue& args) {
                        if(!snapshot_read || prepared) return reject();
                        auto targets=LuaValue::array();
                        for(std::size_t slot=0;slot<plan->effects.size();++slot)
                            if(plan->effects[slot]!=RichonlineHibernateEffect::ineligible &&
                                plan->effects[slot]!=RichonlineHibernateEffect::requester) targets.push_back(slot);
                        if(args!=LuaValue{{"targets",targets},{"frozen_turns",rules.hibernate->frozen_turns}} ||
                            !args.at("frozen_turns").is_number_integer() ||
                            !std::ranges::all_of(args.at("targets"),[](const auto& value){return value.is_number_integer();}))
                            return reject();
                        prepared=true;return LuaValue{};
                    }}
                };
                const auto response=rules.script->call("game.action",{{"payload",lua_bytes(request)},
                    {"opcode",164},{"mode",0},{"map",startup.map_name},{"actor",actor},
                    {"calendar",calendar},{"game_id",board.game_server_id}},bindings);
                if(invalid || !consumed || !snapshot_read || !prepared || !response.is_array() ||
                    response.size()!=1 || !response[0].is_string() || lua_bytes(response[0])!=plan->response40f4)
                    throw CodecError("lua_classic_hibernate_response_invalid");
            }
            std::copy(request.begin(),request.end(),accepted.begin());messages={plan->response40f4};
        } catch(const std::exception& error) {
            if(rules.log) rules.log("richonline_classic_hibernate_refused actor="+std::to_string(actor)+
                " reason="+error.what());
            return {encode_richonline_dice_recovery400b(board.game_server_id)};
        }
        if(sequence!=before_sequence || world.cards!=owners || hibernate_snapshot()!=plan->before)
            throw CodecError("richonline_classic_hibernate_snapshot_stale");
        remember(actor,request);
        // 全部玩家及保护卡先核对；提交段不再分配、调用Lua或外部库存提供者。
        for(std::uint8_t slot=0;slot<active.size();++slot) {
            owners[slot]->commit_inventory(plan->after.actors[slot].inventory.main);
            statuses[slot]=plan->after.actors[slot].status;
        }
        accepted_hibernate[accepted[4]]=accepted;
        if(rules.log) rules.log("richonline_classic_hibernate actor="+std::to_string(actor)+
            " sequence="+std::to_string(sequence)+" turns="+std::to_string(rules.hibernate->frozen_turns));
        return messages;
    }
    std::vector<Bytes> property_card(View request) {
        const auto before_actor=actor;
        const auto before_calendar=calendar;
        const auto before_sequence=sequence;
        const auto owner=world.cards[actor];
        const auto property=world.property;
        const auto ledger=world.ledger;
        const auto research=world.research;
        const auto research_before=research ? research->jobs() : std::vector<std::optional<RichonlineClassicResearchJob>>{};
        const auto before_status=statuses[actor];
        const auto before_raw=raw->actor(actor);
        const auto before_position=board.participants[actor].position;
        const auto before_heading=board.participants[actor].direction;
        const auto source=startup.topology.cell(before_position).property_ref;
        std::optional<RichonlineClassicPropertyCardPlan> plan;
        try {
            if(phase!=Phase::roll || !active[actor] || !owner || owner->actor_slot()!=actor ||
                owner->game_id()!=board.game_server_id || !property || !ledger ||
                (world.research && world.research->active()) ||
                richonline_landing_controlled(before_status) || before_status.stay ||
                !before_raw.hotel1493 || *before_raw.hotel1493!=-1 ||
                !before_raw.hospital1494 || *before_raw.hospital1494!=-1 ||
                !before_raw.jail1495 || *before_raw.jail1495!=-1 ||
                !before_raw.kidnapped1497 || *before_raw.kidnapped1497!=-1 ||
                raw->game().scripted_event83830!=-1)
                throw CodecError("richonline_classic_property_card_unavailable");
            // P+152沿用开局装备原值；只有购地卡读取，其余地产卡不依赖折扣来源。
            const auto land=read_le(request.first(2))==96 ? startup.players[actor].equipment[2] : 0;
            if(land>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
                throw CodecError("richonline_classic_land_equipment_invalid");
            plan=prepare_richonline_classic_property_card(request,calendar,source,static_cast<std::int32_t>(land),
                *owner,*property,*ledger,active,rules.script);
        } catch(const std::exception& error) {
            if(rules.log) rules.log("richonline_classic_property_card_refused actor="+std::to_string(actor)+
                " reason="+error.what());
            return {encode_richonline_dice_recovery400b(board.game_server_id)};
        }
        std::vector<Bytes> messages{plan->response()};
        const auto detail="richonline_classic_property_card actor="+std::to_string(actor)+
            " opcode="+std::to_string(read_le(request.first(2)))+" source="+std::to_string(source)+
            " sequence="+std::to_string(sequence);
        if(phase!=Phase::roll || actor!=before_actor || calendar!=before_calendar || sequence!=before_sequence ||
            world.cards[actor]!=owner || world.property!=property || world.ledger!=ledger ||
            world.research!=research || (research && research->jobs()!=research_before) ||
            statuses[actor]!=before_status || raw->actor(actor)!=before_raw ||
            board.participants[actor].position!=before_position || board.participants[actor].direction!=before_heading ||
            raw->game().scripted_event83830!=-1 || (world.research && world.research->active()))
            throw CodecError("richonline_classic_property_card_stale");
        remember(actor,request);
        if(!commit_richonline_classic_property_card(*owner,*property,*ledger,active,*plan))
            throw CodecError("richonline_classic_property_card_commit_stale");
        // 购地/换地的6071、换屋的6074均先7E3E60解除原产权；该函数立即清首个经典研发登记。
        // 所有可能失败的检查已完成，此处仅noexcept清槽，不能等待未来扫描再取消旧任务。
        const auto opcode=read_le(request.first(2));
        if(research && (opcode==96 || opcode==97 || opcode==98))
            for(const auto& before:plan->properties_before())
                if(before.sprite_type==12 && before.kind==2 && before.owner)
                    research->release_property(before.id,*before.owner);
        if(rules.log) rules.log(detail);
        // 确认包已排地产效果、扣卡和6006；客户端本地动画没有独立网络ACK。
        // 拆屋/怪兽/恶魔保留产权，研究登记由后续原生日历扫描按新kind/level检查。
        return messages;
    }
    std::vector<Bytes> weapon_treaty(View request) {
        const auto before_actor=actor;
        const auto before_calendar=calendar;
        const auto before_sequence=sequence;
        const auto before_status=statuses[actor];
        const auto before_raw=raw->actor(actor);
        const auto before_position=board.participants[actor].position;
        const auto before_heading=board.participants[actor].direction;
        std::optional<RichonlineClassicWeaponTreatyPlan> plan;
        try {
            if(phase!=Phase::roll || !active[actor] || !world.cards[actor] ||
                world.cards[actor]->game_id()!=board.game_server_id ||
                richonline_landing_controlled(before_status) || before_status.stay ||
                !before_raw.hotel1493 || *before_raw.hotel1493!=-1 ||
                !before_raw.hospital1494 || *before_raw.hospital1494!=-1 ||
                !before_raw.jail1495 || *before_raw.jail1495!=-1 ||
                !before_raw.kidnapped1497 || *before_raw.kidnapped1497!=-1 ||
                raw->game().scripted_event83830!=-1)
                throw CodecError("richonline_classic_weapon_treaty_unavailable");
            plan=prepare_richonline_classic_weapon_treaty(request,calendar,actor,world.cards,active,rules.script);
        } catch(const std::exception& error) {
            if(rules.log) rules.log("richonline_classic_weapon_treaty_refused actor="+std::to_string(actor)+
                " reason="+error.what());
            return {encode_richonline_dice_recovery400b(board.game_server_id)};
        }
        std::vector<Bytes> messages{plan->response()};
        if(phase!=Phase::roll || actor!=before_actor || calendar!=before_calendar || sequence!=before_sequence ||
            statuses[actor]!=before_status || raw->actor(actor)!=before_raw ||
            board.participants[actor].position!=before_position || board.participants[actor].direction!=before_heading ||
            raw->game().scripted_event83830!=-1)
            throw CodecError("richonline_classic_weapon_treaty_stale");
        remember(actor,request);
        if(!commit_richonline_classic_weapon_treaty(world.cards,active,*plan))
            throw CodecError("richonline_classic_weapon_treaty_commit_stale");
        if(rules.log) rules.log("richonline_classic_weapon_treaty actor="+std::to_string(actor)+
            " sequence="+std::to_string(sequence));
        // 40DE自身清手牌、扣卡并恢复操作，不追加扣卡包，也不推进到下一位玩家。
        return messages;
    }
    std::vector<Bytes> funds_card(View request) {
        const auto before_actor=actor;
        const auto before_calendar=calendar;
        const auto before_sequence=sequence;
        const auto owner=world.cards[actor];
        const auto before_status=statuses[actor];
        const auto before_raw=raw->actor(actor);
        const auto before_position=board.participants[actor].position;
        const auto before_heading=board.participants[actor].direction;
        std::optional<RichonlineClassicFundsCardPlan> plan;
        std::optional<std::uint8_t> target;
        RichonlineRawActorState target_raw{};
        const auto available=[](const RichonlineRawActorState& state) {
            return state.hotel1493 && state.hospital1494 && state.jail1495 && state.kidnapped1497 &&
                *state.hotel1493==-1 && *state.hospital1494==-1 && *state.jail1495==-1 && *state.kidnapped1497==-1;
        };
        try {
            if(phase!=Phase::roll || !active[actor] || owner->actor_slot()!=actor ||
                owner->game_id()!=board.game_server_id || owner->game_mode()!=0 ||
                richonline_landing_controlled(before_status) || before_status.stay ||
                !available(before_raw) || raw->game().scripted_event83830!=-1)
                throw CodecError("richonline_classic_funds_card_unavailable");
            const auto use=decode_richonline_classic_funds_card(request);
            target=use.target;
            if(target) {
                if(*target>=active.size() || *target==actor || !active[*target])
                    throw CodecError("richonline_classic_funds_card_target_invalid");
                target_raw=raw->actor(*target);
                // 查税/均贫使用64FF10的选人门；冰冻、梦游目标不在四种收容排除项内。
                if(!available(target_raw)) throw CodecError("richonline_classic_funds_card_target_unavailable");
            }
            plan=prepare_richonline_classic_funds_card(request,calendar,*owner,*world.ledger,active,rules.script);
        } catch(const std::exception& error) {
            if(rules.log) rules.log("richonline_classic_funds_card_refused actor="+std::to_string(actor)+
                " reason="+error.what());
            return {encode_richonline_dice_recovery400b(board.game_server_id)};
        }
        std::vector<Bytes> messages{plan->response()};
        if(phase!=Phase::roll || actor!=before_actor || calendar!=before_calendar || sequence!=before_sequence ||
            world.cards[actor]!=owner || statuses[actor]!=before_status || raw->actor(actor)!=before_raw ||
            board.participants[actor].position!=before_position || board.participants[actor].direction!=before_heading ||
            raw->game().scripted_event83830!=-1 || (target && raw->actor(*target)!=target_raw))
            throw CodecError("richonline_classic_funds_card_stale");
        remember(actor,request);
        if(!commit_richonline_classic_funds_card(*owner,*world.ledger,active,*plan))
            throw CodecError("richonline_classic_funds_card_commit_stale");
        if(rules.log) rules.log("richonline_classic_funds_card actor="+std::to_string(actor)+
            " opcode="+std::to_string(read_le(request.first(2)))+" sequence="+std::to_string(sequence));
        // 三张卡均由确认包本地恢复操作；零现金/存款不在这里生成破产或结束回合。
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
            quantity=rules.subscription_quantity ? rules.subscription_quantity(snapshot) :
                world.stocks->maximum_subscription_quantity(actor,use.target,use.stock_slot);
            // 40E6零数量文本表示目标已卖光，不能拿来表示买方买不起或持仓已满。
            if(!quantity) return reject(snapshot.buyer_holding.quantity==0x7fffffffU ?
                "holding_limit" : "insufficient_deposit");
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
        // 节日会同时释放非当前行动者；0015来自各角色自己的连接，不由轮首玩家代报。
        if(opcode==0x15 && request.size()==4) {
            if(phase==Phase::feast_exit) {
                auto exit=std::ranges::find_if(feast_exits,[&](const auto& entry){return entry.actor==sender;});
                if(exit!=feast_exits.end() && !exit->controlled) {
                    if(exit->complete) return {};
                    if(rules.now()>=exit->deadline) throw CodecError("richonline_classic_feast_exit_timeout");
                    remember(sender,request);complete_feast_exit(*exit);return continue_feast_exits();
                }
            }
            // 非行动者的重复节日确认也须在行动槽门之前去重。
            if(was_retired(sender,request)) return {};
        }
        // 旧行动者的迟到选号也可能在换人后抵达；当前待决仍优先，不能吞掉同日再次购买。
        if(opcode==0x29 && !(phase==Phase::lottery && sender==actor && pending_opcode==opcode) &&
            was_retired(sender,request)) return {};
        if((opcode==0x25 || opcode==0x26) && !(phase==Phase::trade && sender==actor && pending_opcode==opcode) &&
            was_retired(sender,request)) return {};
        if(sender!=actor) throw CodecError("richonline_classic_sender_not_active");
        if((phase==Phase::feast_exit || phase==Phase::lottery_draw) && opcode==0x10) {
            const auto roll=std::get<RichonlineMoveRequest10>(parse_richonline_movement_request(request));
            if(roll.parameter!=0) throw CodecError("richonline_classic_roll_parameter_unsupported");
            calendar_roll_requested=true;remember(sender,request);return {};
        }
        if(phase==Phase::turn_event && pending_opcode==opcode) {
            auto result=services.event(context(),request);remember(sender,request);
            return turn_start_result({},std::move(result));
        }
        if(phase==Phase::research && pending_opcode==opcode) {
            auto result=world.research->handle(sender,request,property_entry());remember(sender,request);
            return research_result(std::move(result));
        }
        if(phase==Phase::trade && pending_opcode==opcode) {
            if((opcode==0x26 ? decode_richonline_classic_hotel_request(request) :
                decode_richonline_classic_trade_request(request))!=calendar)
                throw CodecError("richonline_classic_trade_calendar_mismatch");
            auto messages=finish_trade(rules.now()>=trade->deadline);remember(sender,request);return messages;
        }
        if(phase==Phase::lottery && pending_opcode==opcode) {
            auto result=lottery->handle(sender,request,lottery_entry(),news_fines);remember(sender,request);
            return lottery_result(std::move(result));
        }
        if(opcode==0x15) {
            if(request.size()!=4) throw CodecError("richonline_classic_confinement_ack_invalid");
            if(phase==Phase::hotel_exit && !confinement_controlled()) {
                if(!hotel_deadline || rules.now()>=*hotel_deadline)
                    throw CodecError("richonline_classic_hotel_exit_timeout");
                remember(sender,request);return finish_hotel_exit();
            }
            if(phase==Phase::confinement_exit && !confinement_controlled()) {
                remember(sender,request);return finish_confinement_exit();
            }
            if(was_retired(sender,request)) return {};
            throw CodecError("richonline_classic_confinement_ack_out_of_phase");
        }
        if((phase==Phase::hotel_exit || hotel_exit_effects) && confinement_controlled() && opcode==0x10) {
            const auto roll=std::get<RichonlineMoveRequest10>(parse_richonline_movement_request(request));
            if(roll.parameter!=0) throw CodecError("richonline_classic_roll_parameter_unsupported");
            hotel_exit_roll_requested=true;remember(sender,request);return {};
        }
        if(phase==Phase::confinement_exit && confinement_controlled() && opcode==0x10) {
            const auto roll=std::get<RichonlineMoveRequest10>(parse_richonline_movement_request(request));
            if(roll.parameter!=0) throw CodecError("richonline_classic_roll_parameter_unsupported");
            // 受控角色不发0015；先保存早到的自动掷骰意图，等归位后再提交移动事务。
            confinement_exit_roll_requested=true;remember(sender,request);return {};
        }
        // 商店显示时Shift弃卡仍产生0032，独立于0031出售，不增加点券也不结束商店。
        if((phase==Phase::roll || phase==Phase::shop) && opcode==0x32) {
            if(richonline_landing_controlled(statuses[actor]))
                return {encode_richonline_dice_recovery400b(board.game_server_id)};
            const auto discard=parse_richonline_card_discard50(request);
            auto prepared=world.cards[actor]->prepare_discard(discard,static_cast<std::int8_t>(actor));
            auto messages=std::vector<Bytes>{std::move(prepared.confirmation4033)};
            world.cards[actor]->commit_inventory(prepared.remaining_inventory);return messages;
        }
        if(phase==Phase::shop && (opcode==0x30 || opcode==0x31 || opcode==0x35)) {
            auto& shop=*shops[actor];
            const auto before=shop.points();
            auto result=shop.handle(request);
            if(rules.log) rules.log("richonline_classic_shop_request actor="+std::to_string(actor)+
                " calendar="+std::to_string(calendar)+" opcode="+std::to_string(opcode)+
                " index="+std::to_string(request.size()==6 ? std::bit_cast<std::int8_t>(request[4]) : -1)+
                " tickets_before="+std::to_string(before)+" tickets_after="+std::to_string(shop.points())+
                " decision="+shop.last_decision());
            return shop_result(std::move(result));
        }
        if(phase==Phase::roll) {
            if(opcode!=0x10 && richonline_landing_controlled(statuses[actor]))
                return {encode_richonline_dice_recovery400b(board.game_server_id)};
            if(opcode==22) return paid_move(request);
            if(opcode==116) return theft_card(request);
            if(opcode==114 || opcode==115 || opcode==166) return funds_card(request);
            if(opcode==142) return weapon_treaty(request);
            if(opcode==164) return hibernate_card(request);
            if(opcode==96 || opcode==97 || opcode==98 || opcode==99 || opcode==100 || opcode==101 || opcode==102 ||
                opcode==119 || opcode==120 || opcode==123 || opcode==134 || (opcode>=125 && opcode<=129))
                return property_card(request);
            if(opcode==0x96 || opcode==0x97) return stock_card(request);
            if(opcode==103 || (opcode>=137 && opcode<=140)) return immediate_move_card(request);
            if((opcode>=104 && opcode<=107) || opcode==136 || opcode==141) return motion_card(request);
            if(opcode==0x10) {
                const auto roll=std::get<RichonlineMoveRequest10>(parse_richonline_movement_request(request));
                if(roll.parameter!=0) throw CodecError("richonline_classic_roll_parameter_unsupported");
                return random_move(request);
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
            remember(sender,request);return property_result(std::move(result));
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
        if(phase==Phase::frozen_wait) {
            if(!frozen_deadline || rules.now()<*frozen_deadline) return {};
            frozen_deadline.reset();frozen_wait_packet.clear();return advance({});
        }
        if(phase==Phase::hotel_wait || phase==Phase::hotel_exit) {
            if(!hotel_deadline || rules.now()<*hotel_deadline) return {};
            if(phase==Phase::hotel_exit) {
                if(!confinement_controlled()) throw CodecError("richonline_classic_hotel_exit_timeout");
                return finish_hotel_exit();
            }
            hotel_deadline.reset();hotel_wait_packet.clear();return advance({});
        }
        if(phase==Phase::trade) {
            if(!trade) throw CodecError("richonline_classic_trade_pending_missing");
            if(rules.now()>=trade->deadline) return finish_trade(true);
            return {};
        }
        if(phase==Phase::lottery_draw) {
            if(!lottery_draw_deadline || rules.now()<*lottery_draw_deadline) return {};
            lottery_draw_deadline.reset();lottery_draw_packet.clear();
            return after_lottery({});
        }
        if(phase==Phase::lottery) {
            if(auto result=lottery->poll(lottery_entry(),news_fines)) return lottery_result(std::move(*result));
            return {};
        }
        if(phase==Phase::feast_exit) {
            const auto now=rules.now();
            for(auto& exit:feast_exits) if(!exit.complete && now>=exit.deadline) {
                if(!exit.controlled) throw CodecError("richonline_classic_feast_exit_timeout");
                complete_feast_exit(exit);
            }
            return continue_feast_exits();
        }
        if(phase==Phase::turn_event) {
            if(auto result=services.poll(context())) return turn_start_result({},std::move(*result));
            return {};
        }
        if(phase==Phase::research) {
            if(auto result=world.research->poll(property_entry())) return research_result(std::move(*result));
            return {};
        }
        if(phase==Phase::confinement_wait || phase==Phase::confinement_exit) {
            if(!confinement_deadline) throw CodecError("richonline_classic_confinement_deadline_missing");
            if(rules.now()<*confinement_deadline) return {};
            if(phase==Phase::confinement_exit) {
                if(!confinement_controlled()) throw CodecError("richonline_classic_confinement_ack_timeout");
                return finish_confinement_exit();
            }
            confinement_deadline.reset();return advance({});
        }
        if(phase==Phase::kidnap_wait) {
            if(!kidnap_deadline) throw CodecError("richonline_classic_kidnap_deadline_missing");
            if(rules.now()<*kidnap_deadline) return {};
            kidnap_deadline.reset();return advance({});
        }
        if(phase==Phase::bank) {
            if(auto result=bank->poll()) return bank_result(std::move(*result));
        } else if(phase==Phase::shop) {
            if(auto result=shops[actor]->poll()) return shop_result(std::move(*result));
        } else if(phase==Phase::rent_transfer) {
            if(rules.now()>=rent_transfer->deadline) return finish_rent_transfer({calendar,-1,0},true);
        } else if(phase==Phase::property) {
            if(auto result=world.property->poll(property_entry())) {
                return property_result(std::move(*result));
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
    void sent(std::uint8_t sender,View packet) {
        if(terminal) terminal->sent(sender,packet);
        if(phase==Phase::frozen_wait && std::ranges::equal(packet,frozen_wait_packet)) {
            if(sender>=frozen_wait_sent.size()) throw CodecError("richonline_classic_frozen_delivery_actor_invalid");
            frozen_wait_sent[sender]=true;
            if(!frozen_deadline && std::ranges::all_of(frozen_wait_sent,[](bool value){return value;}))
                frozen_deadline=rules.now()+rules.frozen_turn_delay;
        }
        if((phase==Phase::hotel_wait || phase==Phase::hotel_exit) && std::ranges::equal(packet,hotel_wait_packet)) {
            if(sender>=hotel_wait_sent.size()) throw CodecError("richonline_hotel_delivery_actor_invalid");
            hotel_wait_sent[sender]=true;
            // 先等全员收到入店/回合消息再计时，不把网络传输时间扣到动画/离店确认期限里。
            if(!hotel_deadline && std::ranges::all_of(hotel_wait_sent,[](bool value){return value;}))
                hotel_deadline=rules.now()+hotel_delay;
        }
        if(phase!=Phase::lottery_draw || !std::ranges::equal(packet,lottery_draw_packet)) return;
        if(sender>=lottery_draw_sent.size()) throw CodecError("richonline_lottery_delivery_actor_invalid");
        lottery_draw_sent[sender]=true;
        if(!lottery_draw_deadline && std::ranges::all_of(lottery_draw_sent,[](bool value){return value;}))
            lottery_draw_deadline=rules.now()+rules.lottery->draw_delay;
    }
    void disconnect(std::uint8_t sender) {
        if(sender>=disconnected.size() || disconnected[sender]) return;
        disconnected[sender]=true;
        if(!terminal || !terminal->committed())phase=Phase::closed;
        movement.reset();rent_transfer.reset();trade.reset();kidnap_deadline.reset();confinement_deadline.reset();
        hotel_deadline.reset();hotel_wait_packet.clear();hotel_visits.clear();hotel_exit_effects=false;hotel_exit_roll_requested=false;
        feast_exits.clear();calendar_roll_requested=false;
        lottery_draw_deadline.reset();lottery_draw_packet.clear();
        frozen_deadline.reset();frozen_wait_packet.clear();accepted_hibernate={};
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
        session->sent(actor,plain);
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

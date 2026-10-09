#include "storage_detail.hpp"
#include "storage_achievement_detail.hpp"

#include <algorithm>
#include <bit>
#include <cmath>
#include <functional>
#include <limits>
#include <set>

namespace richnet {
using namespace storage_detail;
namespace storage_detail {
void validate_richonline_achievement(const GameSettlementAchievement& value) {
    const auto category=static_cast<std::int32_t>(value.category);
    if(category!=1 && category!=3 && category!=9 && category!=13 && category!=15)
        throw StorageError("ranking_category_unknown");
    if(value.policy.empty() || value.policy.size()>1024 || value.policy.find('\0')!=std::string::npos)
        throw StorageError("ranking_achievement_identity_invalid");
    if(value.score>static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max()))
        throw StorageError("ranking_achievement_score_out_of_wire_range");
}
void richonline_achievement_schema(sqlite3* db) {
    execute(db,R"sql(CREATE TABLE IF NOT EXISTS richonline_achievement_policies(
 category INTEGER PRIMARY KEY CHECK(category IN(1,3,9,13,15)),policy TEXT NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS richonline_achievement_matches(
 role_id INTEGER NOT NULL REFERENCES roles(role_id),match_id TEXT NOT NULL,
 settlement_operation TEXT NOT NULL REFERENCES operations(operation_id),
 category INTEGER NOT NULL REFERENCES richonline_achievement_policies(category),
 score INTEGER NOT NULL CHECK(score BETWEEN 0 AND 2147483647),
 PRIMARY KEY(role_id,match_id,category)) STRICT;)sql");
}
void verify_richonline_achievement(sqlite3* db,std::int64_t role,const std::string& match,
    const std::string& operation,const GameSettlementAchievement& value) {
    Statement prior(db,"SELECT a.score,a.settlement_operation,p.policy FROM richonline_achievement_matches a "
        "JOIN richonline_achievement_policies p ON p.category=a.category WHERE a.role_id=? AND a.match_id=? AND a.category=?");
    prior.bind(1,role);prior.bind(2,match);prior.bind(3,static_cast<std::int32_t>(value.category));
    if(!prior.row() || prior.integer(0)!=static_cast<std::int64_t>(value.score) ||
        prior.text(1)!=operation || prior.text(2)!=value.policy)
        throw StorageError("ranking_achievement_committed_record_invalid");
}
bool insert_richonline_achievement(sqlite3* db,std::int64_t role,const std::string& match,
    const std::string& operation,const GameSettlementAchievement& value) {
    validate_richonline_achievement(value);
    const auto category=static_cast<std::int32_t>(value.category);
    Statement existing_policy(db,"SELECT policy FROM richonline_achievement_policies WHERE category=?");
    existing_policy.bind(1,category);
    if(existing_policy.row()) {
        if(existing_policy.text(0)!=value.policy)throw StorageError("ranking_achievement_policy_conflict");
    } else {
        Statement add(db,"INSERT INTO richonline_achievement_policies(category,policy) VALUES(?,?)");
        add.bind(1,category);add.bind(2,value.policy);add.row();
    }
    Statement prior(db,"SELECT score,settlement_operation FROM richonline_achievement_matches WHERE role_id=? AND match_id=? AND category=?");
    prior.bind(1,role);prior.bind(2,match);prior.bind(3,category);
    if(prior.row()) {
        if(prior.integer(0)!=static_cast<std::int64_t>(value.score) || prior.text(1)!=operation)
            throw StorageError("ranking_achievement_replay_conflict");
        return false;
    }
    Statement total(db,"SELECT COALESCE(SUM(score),0) FROM richonline_achievement_matches WHERE role_id=? AND category=?");
    total.bind(1,role);total.bind(2,category);total.row();
    if(total.integer(0)>std::numeric_limits<std::int32_t>::max()-static_cast<std::int64_t>(value.score))
        throw StorageError("ranking_achievement_score_out_of_wire_range");
    Statement add(db,"INSERT INTO richonline_achievement_matches(role_id,match_id,settlement_operation,category,score) VALUES(?,?,?,?,?)");
    add.bind(1,role);add.bind(2,match);add.bind(3,operation);add.bind(4,category);add.bind(5,value.score);add.row();
    return true;
}
}
namespace {
using Json = nlohmann::json;
constexpr const char* source = "native-game-settlement";
constexpr const char* pledge_source = "native-game-pledge";
constexpr const char* refund_source = "native-game-pledge-refund";
void pledge_schema(sqlite3* db) {
    execute(db,R"sql(CREATE TABLE IF NOT EXISTS game_entry_pledges(
 operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
 match_id TEXT NOT NULL,role_id INTEGER NOT NULL REFERENCES roles(role_id),stage_key TEXT NOT NULL,
 amount INTEGER NOT NULL CHECK(amount BETWEEN 1 AND 2147483647),
 state TEXT NOT NULL CHECK(state IN ('held','refunded','settled')),
 closing_operation TEXT UNIQUE REFERENCES operations(operation_id),
 UNIQUE(match_id,role_id)) STRICT;)sql");
}
void outbox_schema(sqlite3* db) {
    execute(db,R"sql(CREATE TABLE IF NOT EXISTS game_settlement_outbox(
 operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
 role_id INTEGER NOT NULL REFERENCES roles(role_id),match_id TEXT NOT NULL,
 delivery TEXT NOT NULL,next_message INTEGER NOT NULL CHECK(next_message>=0),
 message_count INTEGER NOT NULL CHECK(message_count BETWEEN 3 AND 19),
 CHECK(next_message<=message_count)) STRICT;)sql");
}
void profile_refresh_schema(sqlite3* db) {
    execute(db,R"sql(CREATE TABLE IF NOT EXISTS game_settlement_profile_refreshes(
 operation_id TEXT PRIMARY KEY REFERENCES game_settlement_outbox(operation_id),
 role_id INTEGER NOT NULL REFERENCES roles(role_id),match_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','confirmed')),
 connection_generation TEXT NOT NULL DEFAULT '',attempt INTEGER NOT NULL DEFAULT 0 CHECK(attempt>=0),
 payload TEXT NOT NULL DEFAULT '',UNIQUE(match_id,role_id)) STRICT;)sql");
}
void item_reward_schema(sqlite3* db) {
    execute(db,R"sql(CREATE TABLE IF NOT EXISTS game_settlement_item_rewards(
 operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
 role_id INTEGER NOT NULL REFERENCES roles(role_id),match_id TEXT NOT NULL,stage_key TEXT NOT NULL,
 resource_count INTEGER NOT NULL CHECK(resource_count BETWEEN 1 AND 8),resource_ids TEXT NOT NULL,
 provenance TEXT NOT NULL,state TEXT NOT NULL CHECK(state='unresolved'),
 UNIQUE(match_id,role_id)) STRICT;)sql");
}
Json delivery_json(const GameSettlementDelivery& value) {
    return {{"game_id",value.game_id},{"room_id",value.room_id},{"human_slot",value.human_slot},
        {"rank_image_index",value.rank_image_index},{"opaque_18",value.opaque_18},
        {"show_text_270",value.show_text_270},{"bankrupt_slots",value.bankrupt_slots}};
}
void validate_delivery(const GameSettlementDelivery& value,GameOutcome outcome) {
    if(value.room_id>32767 || value.human_slot<0 || value.human_slot>=8 || value.bankrupt_slots.size()>8)
        throw StorageError("game_settlement_delivery_invalid");
    std::array<bool,8> seen{};
    for(const auto slot:value.bankrupt_slots) {
        if(slot<0 || slot>=8 || seen[static_cast<std::size_t>(slot)])throw StorageError("game_settlement_delivery_invalid");
        seen[static_cast<std::size_t>(slot)]=true;
    }
    if(outcome==GameOutcome::win && seen[static_cast<std::size_t>(value.human_slot)])
        throw StorageError("game_settlement_delivery_invalid");
}
GameSettlementDelivery delivery_from_json(const Json& value,GameOutcome outcome) {
    auto bounded=[&](const Json& field,std::int64_t low,std::int64_t high) {
        if(!field.is_number_integer() || field<low || field>high)throw StorageError("game_settlement_outbox_invalid");
    };
    bounded(value.at("game_id"),0,65535);bounded(value.at("room_id"),0,32767);
    bounded(value.at("human_slot"),0,7);bounded(value.at("rank_image_index"),-128,127);
    bounded(value.at("opaque_18"),0,255);
    if(!value.at("bankrupt_slots").is_array())throw StorageError("game_settlement_outbox_invalid");
    for(const auto& slot:value.at("bankrupt_slots"))bounded(slot,0,7);
    GameSettlementDelivery result{value.at("game_id").get<std::uint16_t>(),value.at("room_id").get<std::uint32_t>(),
        value.at("human_slot").get<std::int8_t>(),value.at("rank_image_index").get<std::int8_t>(),
        value.at("opaque_18").get<std::uint8_t>(),value.at("show_text_270").get<bool>(),
        value.at("bankrupt_slots").get<std::vector<std::int8_t>>()};
    validate_delivery(result,outcome);return result;
}
void text(const std::string& value, std::size_t maximum, const char* error) {
    if(value.empty() || value.size()>maximum || value.find('\0')!=std::string::npos) throw StorageError(error);
}
std::uint32_t profile_u32(std::span<const std::uint8_t> bytes,std::size_t offset) {
    std::uint32_t result=0;
    for(std::size_t i=0;i<4;++i)result|=static_cast<std::uint32_t>(bytes[offset+i])<<static_cast<unsigned>(i*8);
    return result;
}
double profile_f64(std::span<const std::uint8_t> bytes,std::size_t offset) {
    std::uint64_t result=0;
    for(std::size_t i=0;i<8;++i)result|=static_cast<std::uint64_t>(bytes[offset+i])<<static_cast<unsigned>(i*8);
    return std::bit_cast<double>(result);
}
void validate_profile(std::span<const std::uint8_t> bytes,std::uint32_t expected_actor) {
    if(bytes.size()!=144 || profile_u32(bytes,0)!=expected_actor ||
        std::find(bytes.begin()+112,bytes.end(),std::uint8_t{0})==bytes.end())
        throw StorageError("game_settlement_refresh_profile_invalid");
    for(const auto offset:{80U,88U,96U}) {
        const auto amount=profile_f64(bytes,offset);
        if(!std::isfinite(amount) || amount<0)throw StorageError("game_settlement_refresh_profile_invalid");
    }
}
std::string profile_json(std::span<const std::uint8_t> bytes) {
    return Json(std::vector<std::uint8_t>(bytes.begin(),bytes.end())).dump();
}
// Validate the durable intent against its canonical settlement and exact
// terminal outbox boundary before exposing or acknowledging notification work.
GameSettlementProfileRefresh refresh_intent(sqlite3* db,const std::string& username,std::int64_t role,
                                           const std::string& operation) {
    Statement row(db,"SELECT r.match_id,b.delivery,b.next_message,b.message_count,o.request,o.source,o.role_id "
        "FROM game_settlement_profile_refreshes r JOIN game_settlement_outbox b ON b.operation_id=r.operation_id "
        "JOIN operations o ON o.operation_id=r.operation_id "
        "WHERE r.operation_id=? AND r.role_id=? AND b.role_id=r.role_id AND b.match_id=r.match_id");
    row.bind(1,operation);row.bind(2,role);
    if(!row.row())throw StorageError("game_settlement_refresh_missing");
    try {
        const auto canonical=Json::parse(row.text(4)),delivery=Json::parse(row.text(1));
        const auto name=canonical.at("outcome").get<std::string>();
        if(name!="win" && name!="loss" && name!="draw")throw StorageError("game_settlement_refresh_invalid");
        const auto outcome=name=="win"?GameOutcome::win:name=="loss"?GameOutcome::loss:GameOutcome::draw;
        const auto parsed=delivery_from_json(delivery,outcome);
        if(row.text(5)!=source || row.integer(6)!=role || canonical.at("username")!=username ||
            canonical.at("role_id")!=role || canonical.at("match_id")!=row.text(0) || canonical.at("delivery")!=delivery ||
            row.integer(3)!=static_cast<std::int64_t>(parsed.bankrupt_slots.size()*2+3))
            throw StorageError("game_settlement_refresh_invalid");
        if(row.integer(2)!=row.integer(3))throw StorageError("game_settlement_refresh_lobby_not_delivered");
        return {operation,row.text(0),role};
    }catch(const Json::exception&){throw StorageError("game_settlement_refresh_invalid");}
}
const char* outcome_name(GameOutcome outcome) {
    switch(outcome) {
    case GameOutcome::win:return "win";
    case GameOutcome::loss:return "loss";
    case GameOutcome::draw:return "draw";
    }
    throw StorageError("game_settlement_outcome_invalid");
}
Json item_reward_json(const GameSettlementItemReward& value) {
    return {{"resource_count",value.resource_count},{"resource_ids",value.resource_ids}};
}
void validate_item_reward(const GameSettlementItemReward& value) {
    if(value.resource_count==0 || value.resource_count>8 || value.resource_ids.size()!=value.resource_count)
        throw StorageError("game_settlement_item_reward_invalid");
}
GameSettlementItemReward item_reward_from_json(const Json& value) {
    if(!value.at("resource_count").is_number_integer() || value.at("resource_count")<1 || value.at("resource_count")>8 ||
        !value.at("resource_ids").is_array())throw StorageError("game_settlement_item_reward_invalid");
    GameSettlementItemReward result{value.at("resource_count").get<std::uint32_t>(),{}};
    for(const auto& entry:value.at("resource_ids")) {
        if(!entry.is_number_integer() || entry<std::numeric_limits<std::int32_t>::min() ||
            entry>std::numeric_limits<std::int32_t>::max())throw StorageError("game_settlement_item_reward_invalid");
        result.resource_ids.push_back(entry.get<std::int32_t>());
    }
    validate_item_reward(result);return result;
}
Json reward_json(const GameSettlementReward& reward) {
    Json result{{"experience",reward.experience},{"gold_return",reward.gold_return},{"bonus_gold",reward.bonus_gold}};
    // Preserve the exact historical canonical shape of empty-item operations.
    if(reward.items)result["items"]=item_reward_json(*reward.items);
    return result;
}
GameSettlementReward reward_from_json(const Json& value) {
    std::optional<GameSettlementItemReward> items;
    if(value.contains("items"))items=item_reward_from_json(value.at("items"));
    return {value.at("experience").get<std::uint32_t>(),value.at("gold_return").get<std::uint32_t>(),
        value.at("bonus_gold").get<std::uint32_t>(),std::move(items)};
}
void validate_reward(const GameSettlementReward& reward) {
    // NEW401B uses a signed short for the per-match experience award and
    // signed rendering for both monetary values.
    if(reward.experience>32767 || reward.gold_return>2147483647U || reward.bonus_gold>2147483647U)
        throw StorageError("game_settlement_reward_out_of_range");
    if(reward.items)validate_item_reward(*reward.items);
}
Json request_json(const std::string& username,std::int64_t role,const GameSettlementRequest& request) {
    Json result{{"username",username},{"role_id",role},{"match_id",request.match_id},{"stage_key",request.stage_key},
        {"outcome",outcome_name(request.outcome)},{"pawn_gold",request.pawn_gold},
        {"pledge_charge_operation",request.pledge_charge_operation ? Json(*request.pledge_charge_operation) : Json(nullptr)},
        {"delivery",request.delivery?delivery_json(*request.delivery):Json(nullptr)},
        {"policy",{{"provenance",request.policy.provenance},{"first_win",reward_json(request.policy.first_win)},
            {"repeat_win",reward_json(request.policy.repeat_win)},{"loss",reward_json(request.policy.loss)},
            {"draw",reward_json(request.policy.draw)},{"levels",request.policy.cumulative_level_experience},
            {"winning_pledge_return",request.policy.winning_pledge_return}}}};
    // Preserve canonical bytes for historical requests without observations.
    if(request.achievement) {
        const auto& value=*request.achievement;
        result["achievement"]={{"category",static_cast<std::int32_t>(value.category)},
            {"score",value.score},{"policy",value.policy}};
        if(value.ledger_revision)result["achievement"]["ledger_revision"]=*value.ledger_revision;
    }
    return result;
}
std::uint32_t count(const Json& role,const char* key) {
    const auto value=role.at(key).get<std::int64_t>();
    if(value<0 || value>2147483647) throw StorageError("game_settlement_stored_counter_invalid");
    return static_cast<std::uint32_t>(value);
}
GameSettlementResult result_from_json(const Json& value) {
    const auto reward=reward_from_json(value.at("reward")); validate_reward(reward);
    GameSettlementResult result{true,value.at("first_clear").get<bool>(),reward,
        value.at("level_before").get<std::uint32_t>(),value.at("level_after").get<std::uint32_t>(),
        value.at("experience_after").get<std::uint32_t>(),value.at("gold_after").get<double>(),
        value.at("wins_after").get<std::uint32_t>(),value.at("losses_after").get<std::uint32_t>(),
        value.at("draws_after").get<std::uint32_t>()};
    if(result.level_before>20 || result.level_after>20 || result.level_after<result.level_before ||
        result.experience_after>2147483647U || !std::isfinite(result.gold_after) || result.gold_after<0 ||
        result.wins_after>2147483647U || result.losses_after>2147483647U || result.draws_after>2147483647U)
        throw StorageError("game_settlement_result_invalid");
    return result;
}
double owned_gold(sqlite3* db,const std::string& username,std::int64_t role) {
    Statement owner(db,"SELECT gold FROM roles WHERE username=? AND role_id=?");
    owner.bind(1,username);owner.bind(2,role);
    if(!owner.row())throw StorageError("game_pledge_role_not_owned");
    const auto value=owner.record().at("gold").get<double>();
    if(!std::isfinite(value) || value<0)throw StorageError("game_pledge_balance_invalid");
    return value;
}
std::optional<GameEntryPledgeResult> prior_pledge(sqlite3* db,std::int64_t role,const std::string& operation,
                                              const char* kind,const Json& request) {
    Statement prior(db,"SELECT role_id,source,request,result FROM operations WHERE operation_id=?");
    prior.bind(1,operation);
    if(!prior.row())return {};
    if(prior.integer(0)!=role || prior.text(1)!=kind || prior.text(2)!=request.dump())
        throw StorageError("game_pledge_operation_conflict");
    try {
        const auto value=Json::parse(prior.text(3)).at("gold_after").get<double>();
        if(!std::isfinite(value) || value<0)throw StorageError("game_pledge_result_invalid");
        return GameEntryPledgeResult{true,value};
    }catch(const Json::exception&){throw StorageError("game_pledge_result_invalid");}
}
void pledge_money(sqlite3* db,const std::string& username,std::int64_t role,double before,double after,
                  const char* kind,const std::string& reason,const std::string& operation,const Json& request) {
    Statement update(db,"UPDATE roles SET gold=? WHERE username=? AND role_id=?");
    update.bind(1,after);update.bind(2,username);update.bind(3,role);update.row();
    Statement audit(db,"INSERT INTO audit(role_id,username,field,old_value,new_value,source,reason,operation_id) VALUES(?,?,'gold',?,?,?,?,?)");
    audit.bind(1,role);audit.bind(2,username);audit.bind(3,Json(before).dump());audit.bind(4,Json(after).dump());
    audit.bind(5,kind);audit.bind(6,reason);audit.bind(7,operation);audit.row();
    Statement receipt(db,"INSERT INTO operations(operation_id,role_id,source,reason,request,result) VALUES(?,?,?,?,?,?)");
    receipt.bind(1,operation);receipt.bind(2,role);receipt.bind(3,kind);receipt.bind(4,reason);
    receipt.bind(5,request.dump());receipt.bind(6,Json{{"gold_after",after}}.dump());receipt.row();
}
}

GameEntryPledgeResult Storage::reserve_game_pledge(const std::string& username,std::int64_t role,
                                                 const GameEntryPledgeRequest& request) {
    const std::lock_guard lock(mutex_);
    if(profile_!=ClientProfile::richonline)throw StorageError("game_pledge_profile_invalid");
    text(request.operation_id,256,"game_pledge_operation_invalid");
    text(request.match_id,256,"game_pledge_match_invalid");
    text(request.stage_key,128,"game_pledge_stage_invalid");
    if(request.amount==0 || request.amount>2147483647U)throw StorageError("game_pledge_amount_invalid");
    const Json canonical{{"username",username},{"role_id",role},{"match_id",request.match_id},
        {"stage_key",request.stage_key},{"amount",request.amount}};
    Transaction transaction(db_);const auto before=owned_gold(db_,username,role);
    if(const auto old=prior_pledge(db_,role,request.operation_id,pledge_source,canonical)) {
        Statement state(db_,"SELECT state FROM game_entry_pledges WHERE operation_id=?");
        state.bind(1,request.operation_id);
        if(!state.row() || state.text(0)!="held")throw StorageError("game_pledge_not_held");
        transaction.commit();return *old;
    }
    pledge_schema(db_);
    Statement existing(db_,"SELECT 1 FROM game_entry_pledges WHERE match_id=? AND role_id=?");
    existing.bind(1,request.match_id);existing.bind(2,role);
    if(existing.row())throw StorageError("game_pledge_match_already_reserved");
    if(before<request.amount)throw StorageError("game_pledge_insufficient_funds");
    const auto after=before-static_cast<double>(request.amount);
    if(!std::isfinite(after) || before-after!=request.amount)throw StorageError("game_pledge_precision_invalid");
    pledge_money(db_,username,role,before,after,pledge_source,"boss entry pledge",request.operation_id,canonical);
    Statement hold(db_,"INSERT INTO game_entry_pledges(operation_id,match_id,role_id,stage_key,amount,state) VALUES(?,?,?,?,?,'held')");
    hold.bind(1,request.operation_id);hold.bind(2,request.match_id);hold.bind(3,role);
    hold.bind(4,request.stage_key);hold.bind(5,request.amount);hold.row();
    transaction.commit();return {false,after};
}

GameEntryPledgeResult Storage::refund_game_pledge(const std::string& username,std::int64_t role,
                                                const GameEntryPledgeRefund& request) {
    const std::lock_guard lock(mutex_);
    if(profile_!=ClientProfile::richonline)throw StorageError("game_pledge_profile_invalid");
    text(request.operation_id,256,"game_pledge_operation_invalid");
    text(request.pledge_operation,256,"game_pledge_operation_invalid");
    text(request.reason,1024,"game_pledge_refund_reason_invalid");
    const Json canonical{{"username",username},{"role_id",role},{"pledge_operation",request.pledge_operation},{"reason",request.reason}};
    Transaction transaction(db_);const auto before=owned_gold(db_,username,role);
    if(const auto old=prior_pledge(db_,role,request.operation_id,refund_source,canonical)) {
        transaction.commit();return *old;
    }
    pledge_schema(db_);
    Statement pledge(db_,"SELECT amount,state FROM game_entry_pledges WHERE operation_id=? AND role_id=?");
    pledge.bind(1,request.pledge_operation);pledge.bind(2,role);
    if(!pledge.row())throw StorageError("game_pledge_not_reserved");
    if(pledge.text(1)!="held")throw StorageError("game_pledge_not_held");
    const auto amount=pledge.integer(0);const auto after=before+static_cast<double>(amount);
    if(!std::isfinite(after) || after-before!=static_cast<double>(amount))throw StorageError("game_pledge_precision_invalid");
    pledge_money(db_,username,role,before,after,refund_source,request.reason,request.operation_id,canonical);
    Statement close(db_,"UPDATE game_entry_pledges SET state='refunded',closing_operation=? WHERE operation_id=?");
    close.bind(1,request.operation_id);close.bind(2,request.pledge_operation);close.row();
    transaction.commit();return {false,after};
}

GameSettlementResult Storage::settle_game(const std::string& username,std::int64_t role_id,
                                         const GameSettlementRequest& request) {
    const std::lock_guard lock(mutex_);
    if(profile_!=ClientProfile::richonline) throw StorageError("game_settlement_profile_invalid");
    text(request.operation_id,256,"game_settlement_operation_invalid");
    text(request.match_id,256,"game_settlement_match_invalid");
    text(request.stage_key,128,"game_settlement_stage_invalid");
    text(request.policy.provenance,1024,"game_settlement_policy_missing");
    (void)outcome_name(request.outcome);
    if(request.delivery)validate_delivery(*request.delivery,request.outcome);
    if(request.achievement)validate_richonline_achievement(*request.achievement);
    for(const auto& reward:{request.policy.first_win,request.policy.repeat_win,request.policy.loss,request.policy.draw})
        validate_reward(reward);
    const auto& levels=request.policy.cumulative_level_experience;
    if(levels.front()!=0 || levels.back()>2147483647U ||
        std::adjacent_find(levels.begin(),levels.end(),std::greater_equal<>())!=levels.end())
        throw StorageError("game_settlement_levels_invalid");
    if(request.pawn_gold>2147483647U || ((request.pawn_gold==0)==request.pledge_charge_operation.has_value()))
        throw StorageError("game_settlement_pledge_binding_invalid");
    if(request.policy.winning_pledge_return>request.pawn_gold ||
        request.policy.winning_pledge_return>request.policy.first_win.gold_return ||
        request.policy.winning_pledge_return>request.policy.repeat_win.gold_return)
        throw StorageError("game_settlement_pledge_return_invalid");
    if(request.pledge_charge_operation) text(*request.pledge_charge_operation,256,"game_settlement_pledge_binding_invalid");
    const auto canonical=request_json(username,role_id,request);
    Transaction transaction(db_);
    Statement owner(db_,"SELECT * FROM roles WHERE username=? AND role_id=?");
    owner.bind(1,username);owner.bind(2,role_id);
    if(!owner.row()) throw StorageError("game_settlement_role_not_owned");
    const auto before=owner.record();
    Statement prior(db_,"SELECT role_id,source,request,result FROM operations WHERE operation_id=?");
    prior.bind(1,request.operation_id);
    if(prior.row()) {
        if(prior.integer(0)!=role_id || prior.text(1)!=source || prior.text(2)!=canonical.dump())
            throw StorageError("game_settlement_operation_conflict");
        if(request.achievement)verify_richonline_achievement(db_,role_id,request.match_id,request.operation_id,*request.achievement);
        try { auto result=result_from_json(Json::parse(prior.text(3)));transaction.commit();return result; }
        catch(const Json::exception&) {throw StorageError("game_settlement_result_invalid");}
    }
    pledge_schema(db_);
    // Additive tables are created within the first settlement transaction;
    // the shared legacy schema/version is unchanged.
    execute(db_,R"sql(
CREATE TABLE IF NOT EXISTS game_settlements(
 match_id TEXT NOT NULL,role_id INTEGER NOT NULL REFERENCES roles(role_id),
 operation_id TEXT NOT NULL UNIQUE REFERENCES operations(operation_id),
 stage_key TEXT NOT NULL,outcome TEXT NOT NULL CHECK(outcome IN ('win','loss','draw')),
 pledge_operation TEXT UNIQUE REFERENCES operations(operation_id),
 PRIMARY KEY(match_id,role_id)) STRICT;
CREATE TABLE IF NOT EXISTS game_stage_progress(
 role_id INTEGER NOT NULL REFERENCES roles(role_id),stage_key TEXT NOT NULL,
 wins INTEGER NOT NULL CHECK(wins BETWEEN 1 AND 2147483647),
 first_operation TEXT NOT NULL REFERENCES operations(operation_id),
 last_operation TEXT NOT NULL REFERENCES operations(operation_id),
 PRIMARY KEY(role_id,stage_key)) STRICT;
)sql");
    Statement existing(db_,"SELECT 1 FROM game_settlements WHERE match_id=? AND role_id=?");
    existing.bind(1,request.match_id);existing.bind(2,role_id);
    if(existing.row()) throw StorageError("game_settlement_match_already_settled");
    if(request.pledge_charge_operation) {
        Statement charge(db_,"SELECT role_id,source,request,result FROM operations WHERE operation_id=?");
        charge.bind(1,*request.pledge_charge_operation);
        if(!charge.row() || charge.integer(0)!=role_id || charge.text(1)!=pledge_source)
            throw StorageError("game_settlement_pledge_not_debited");
        try {
            const auto paid=Json::parse(charge.text(2));
            if(paid.at("username")!=username || paid.at("role_id")!=role_id ||
                paid.at("amount").get<double>()!=static_cast<double>(request.pawn_gold) ||
                paid.at("match_id")!=request.match_id || paid.at("stage_key")!=request.stage_key)
                throw StorageError("game_settlement_pledge_not_debited");
        } catch(const Json::exception&) {throw StorageError("game_settlement_pledge_not_debited");}
        Statement claimed(db_,"SELECT 1 FROM game_settlements WHERE pledge_operation=?");
        claimed.bind(1,*request.pledge_charge_operation);
        if(claimed.row()) throw StorageError("game_settlement_pledge_already_claimed");
    }
    Statement held(db_,"SELECT operation_id,amount,state,stage_key FROM game_entry_pledges WHERE match_id=? AND role_id=?");
    held.bind(1,request.match_id);held.bind(2,role_id);
    const auto has_pledge=held.row();
    if(request.pledge_charge_operation) {
        if(!has_pledge || held.text(0)!=*request.pledge_charge_operation || held.integer(1)!=request.pawn_gold ||
            held.text(2)!="held" || held.text(3)!=request.stage_key)
            throw StorageError("game_settlement_pledge_not_held");
    } else if(has_pledge) throw StorageError("game_settlement_pledge_binding_invalid");
    Statement progress(db_,"SELECT wins FROM game_stage_progress WHERE role_id=? AND stage_key=?");
    progress.bind(1,role_id);progress.bind(2,request.stage_key);
    const auto previous_wins=progress.row()?progress.integer(0):0;
    const bool first=request.outcome==GameOutcome::win && previous_wins==0;
    const auto reward=request.outcome==GameOutcome::win ? (first?request.policy.first_win:request.policy.repeat_win) :
        request.outcome==GameOutcome::loss ? request.policy.loss : request.policy.draw;
    const auto old_exp=count(before,"experience");
    if(reward.experience>2147483647U-old_exp) throw StorageError("game_settlement_experience_overflow");
    const auto next_exp=old_exp+reward.experience;
    const auto old_level=count(before,"level");
    if(old_level>20) throw StorageError("game_settlement_stored_counter_invalid");
    const auto resource_level=static_cast<std::uint32_t>(std::upper_bound(levels.begin(),levels.end(),next_exp)-levels.begin()-1);
    const auto next_level=std::max(old_level,resource_level);
    const auto gold=before.at("gold").get<double>();
    const auto credit=static_cast<double>(reward.gold_return)+static_cast<double>(reward.bonus_gold);
    const auto next_gold=gold+credit;
    if(!std::isfinite(gold) || gold<0 || !std::isfinite(next_gold) || next_gold-gold!=credit)
        throw StorageError("game_settlement_gold_precision_invalid");
    const auto field=request.outcome==GameOutcome::win?"wins":request.outcome==GameOutcome::loss?"losses":"draws";
    auto after=before; after["experience"]=next_exp;after["level"]=next_level;after["gold"]=next_gold;
    const auto old_count=count(before,field);
    if(old_count==2147483647U || (request.outcome==GameOutcome::win && previous_wins==2147483647))
        throw StorageError("game_settlement_counter_overflow");
    after[field]=old_count+1;
    const GameSettlementResult result{false,first,reward,old_level,next_level,next_exp,next_gold,
        count(after,"wins"),count(after,"losses"),count(after,"draws")};
    const Json saved{{"first_clear",first},{"reward",reward_json(reward)},{"level_before",old_level},
        {"level_after",next_level},{"experience_after",next_exp},{"gold_after",next_gold},
        {"wins_after",result.wins_after},{"losses_after",result.losses_after},{"draws_after",result.draws_after}};
    Statement update(db_,"UPDATE roles SET experience=?,level=?,gold=?,wins=?,losses=?,draws=? WHERE role_id=? AND username=?");
    update.bind(1,next_exp);update.bind(2,next_level);update.bind(3,next_gold);update.bind(4,result.wins_after);
    update.bind(5,result.losses_after);update.bind(6,result.draws_after);update.bind(7,role_id);update.bind(8,username);update.row();
    for(const auto* name:{"experience","level","gold","wins","losses","draws"}) {
        if(before.at(name)==after.at(name)) continue;
        Statement audit(db_,"INSERT INTO audit(role_id,username,field,old_value,new_value,source,reason,operation_id) VALUES(?,?,?,?,?,?,?,?)");
        audit.bind(1,role_id);audit.bind(2,username);audit.bind(3,name);audit.bind(4,before.at(name).dump());
        audit.bind(5,after.at(name).dump());audit.bind(6,source);audit.bind(7,request.policy.provenance);audit.bind(8,request.operation_id);audit.row();
    }
    Statement operation(db_,"INSERT INTO operations(operation_id,role_id,source,reason,request,result) VALUES(?,?,?,?,?,?)");
    operation.bind(1,request.operation_id);operation.bind(2,role_id);operation.bind(3,source);
    operation.bind(4,request.policy.provenance);operation.bind(5,canonical.dump());operation.bind(6,saved.dump());operation.row();
    Statement complete(db_,"INSERT INTO game_settlements(match_id,role_id,operation_id,stage_key,outcome,pledge_operation) VALUES(?,?,?,?,?,?)");
    complete.bind(1,request.match_id);complete.bind(2,role_id);complete.bind(3,request.operation_id);
    complete.bind(4,request.stage_key);complete.bind(5,outcome_name(request.outcome));
    complete.bind(6,request.pledge_charge_operation?Json(*request.pledge_charge_operation):Json(nullptr));complete.row();
    if(request.achievement) {
        richonline_achievement_schema(db_);
        if(!insert_richonline_achievement(db_,role_id,request.match_id,request.operation_id,*request.achievement))
            throw StorageError("ranking_achievement_unsettled_record_exists");
    }
    if(reward.items) {
        item_reward_schema(db_);
        Statement pending(db_,"INSERT INTO game_settlement_item_rewards(operation_id,role_id,match_id,stage_key,resource_count,resource_ids,provenance,state) VALUES(?,?,?,?,?,?,?,'unresolved')");
        pending.bind(1,request.operation_id);pending.bind(2,role_id);pending.bind(3,request.match_id);pending.bind(4,request.stage_key);
        pending.bind(5,reward.items->resource_count);pending.bind(6,Json(reward.items->resource_ids).dump());
        pending.bind(7,request.policy.provenance);pending.row();
        Statement audit(db_,"INSERT INTO audit(role_id,username,field,old_value,new_value,source,reason,operation_id) VALUES(?,?,'pending_item_reward','null',?,?,?,?)");
        audit.bind(1,role_id);audit.bind(2,username);audit.bind(3,item_reward_json(*reward.items).dump());
        audit.bind(4,source);audit.bind(5,request.policy.provenance);audit.bind(6,request.operation_id);audit.row();
    }
    if(request.outcome==GameOutcome::win) {
        Statement write(db_,"INSERT INTO game_stage_progress(role_id,stage_key,wins,first_operation,last_operation) VALUES(?,?,1,?,?) "
            "ON CONFLICT(role_id,stage_key) DO UPDATE SET wins=wins+1,last_operation=excluded.last_operation");
        write.bind(1,role_id);write.bind(2,request.stage_key);write.bind(3,request.operation_id);write.bind(4,request.operation_id);write.row();
    }
    if(request.pledge_charge_operation) {
        Statement close(db_,"UPDATE game_entry_pledges SET state='settled',closing_operation=? WHERE operation_id=?");
        close.bind(1,request.operation_id);close.bind(2,*request.pledge_charge_operation);close.row();
    }
    if(request.delivery) {
        outbox_schema(db_);
        Statement enqueue(db_,"INSERT INTO game_settlement_outbox(operation_id,role_id,match_id,delivery,next_message,message_count) VALUES(?,?,?,?,0,?)");
        enqueue.bind(1,request.operation_id);enqueue.bind(2,role_id);enqueue.bind(3,request.match_id);
        enqueue.bind(4,delivery_json(*request.delivery).dump());
        enqueue.bind(5,request.delivery->bankrupt_slots.size()*2+3);enqueue.row();
        profile_refresh_schema(db_);
        Statement refresh(db_,"INSERT INTO game_settlement_profile_refreshes(operation_id,role_id,match_id,state) VALUES(?,?,?,'pending')");
        refresh.bind(1,request.operation_id);refresh.bind(2,role_id);refresh.bind(3,request.match_id);refresh.row();
    }
    transaction.commit();return result;
}

std::vector<GameSettlementPendingItemReward> Storage::pending_game_settlement_item_rewards(
    const std::string& username,std::int64_t role) {
    const std::lock_guard lock(mutex_);
    if(profile_!=ClientProfile::richonline)throw StorageError("game_settlement_profile_invalid");
    Transaction transaction(db_);(void)owned_gold(db_,username,role);item_reward_schema(db_);
    Statement resolution_table(db_,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='game_settlement_item_resolutions'");
    const bool has_resolutions=resolution_table.row();
    const std::string query="SELECT r.operation_id,r.match_id,r.stage_key,r.resource_count,r.resource_ids,r.provenance,o.request,o.result,o.source "
        "FROM game_settlement_item_rewards r JOIN operations o ON o.operation_id=r.operation_id "
        "WHERE r.role_id=? AND o.role_id=? AND r.state='unresolved' ORDER BY r.rowid";
    Statement rows(db_,query.c_str());
    rows.bind(1,role);rows.bind(2,role);std::vector<GameSettlementPendingItemReward> result;
    while(rows.row()) {
        try {
            const auto canonical=Json::parse(rows.text(6));const auto receipt=Json::parse(rows.text(7));
            const Json specification{{"resource_count",rows.integer(3)},{"resource_ids",Json::parse(rows.text(4))}};
            auto parsed=item_reward_from_json(specification);
            if(rows.text(8)!=source || canonical.at("username")!=username || canonical.at("role_id")!=role ||
                canonical.at("match_id")!=rows.text(1) || canonical.at("stage_key")!=rows.text(2) ||
                canonical.at("policy").at("provenance")!=rows.text(5) || receipt.at("reward").at("items")!=specification)
                throw StorageError("game_settlement_pending_item_reward_invalid");
            if(has_resolutions) {
                Statement resolution(db_,"SELECT x.role_id,x.policy_identifier,x.evidence,x.date_version,x.grant_count,"
                    "i.role_id,i.source,i.request,i.result FROM game_settlement_item_resolutions x "
                    "JOIN operations i ON i.operation_id=x.operation_id WHERE x.settlement_operation=?");
                resolution.bind(1,rows.text(0));
                if(resolution.row()) {
                    try {
                        const auto request=Json::parse(resolution.text(7)),result_value=Json::parse(resolution.text(8));
                        const auto version=resolution.integer(3);
                        const auto mode=version==2005?"original-2005":"richonline-inventory-date-2021-v1";
                        if(resolution.integer(0)!=role || resolution.integer(5)!=role || resolution.text(6)!="native-game-item-resolution" ||
                            (version!=2005 && version!=2021) || request.at("username")!=username || request.at("role_id")!=role ||
                            request.at("settlement_operation")!=rows.text(0) || request.at("policy_identifier")!=resolution.text(1) ||
                            request.at("evidence")!=resolution.text(2) || request.at("key_date_version")!=mode ||
                            !request.at("selections").is_array() || request.at("selections").empty() || request.at("selections").size()>8)
                            throw StorageError("game_settlement_resolved_item_reward_invalid");
                        Json units=Json::array();std::set<std::uint32_t> indexes,keys;
                        for(const auto& selected:request.at("selections")) {
                            const auto& index=selected.at("resource_index");const auto& quantity=selected.at("quantity");
                            const auto& instances=selected.at("instances");
                            if(!index.is_number_integer() || index<0 || index>=parsed.resource_ids.size() ||
                                !quantity.is_number_integer() || quantity<1 || quantity>56 || !instances.is_array() ||
                                instances.size()!=quantity.get<std::size_t>() || !indexes.insert(index.get<std::uint32_t>()).second)
                                throw StorageError("game_settlement_resolved_item_reward_invalid");
                            for(const auto& item:instances) {
                                const auto& key=item.at("owned_key");const auto& expiry=item.at("expires_at");const auto& activation=item.at("activation");
                                if(!key.is_number_integer() || key<1 || key>2147483647 ||
                                    (key.get<std::uint32_t>()&4095U)!=static_cast<std::uint32_t>(parsed.resource_ids[index.get<std::size_t>()]) ||
                                    !keys.insert(key.get<std::uint32_t>()).second ||
                                    (!expiry.is_null() && (!expiry.is_number_integer() || expiry<=0 || expiry>std::numeric_limits<std::int64_t>::max())) ||
                                    (activation!="active" && activation!="requires_activation") ||
                                    ((key.get<std::uint32_t>()>>12U)&15U)>2 || (key.get<std::uint32_t>()&0x10000U)!=0 ||
                                    ((key.get<std::uint32_t>()&0x40000000U)!=0)!=(activation=="requires_activation"))
                                    throw StorageError("game_settlement_resolved_item_reward_invalid");
                                try {
                                    const auto epoch=version==2005?RichonlineInventoryDateVersion::original_2005:
                                        RichonlineInventoryDateVersion::compat_2021_v1;
                                    if(richonline_inventory_key_from_expiry(key.get<std::uint32_t>(),expiry.is_null()?0:expiry.get<std::int64_t>(),epoch)!=key)
                                        throw StorageError("game_settlement_resolved_item_reward_invalid");
                                }catch(const CodecError&){throw StorageError("game_settlement_resolved_item_reward_invalid");}
                                auto unit=item;unit["resource_index"]=index;units.push_back(std::move(unit));
                            }
                        }
                        if(units.empty() || units.size()>56 || resolution.integer(4)!=static_cast<std::int64_t>(units.size()) ||
                            result_value!=Json{{"items",units}})
                            throw StorageError("game_settlement_resolved_item_reward_invalid");
                        continue;
                    }catch(const Json::exception&){throw StorageError("game_settlement_resolved_item_reward_invalid");}
                }
            }
            result.push_back({rows.text(0),rows.text(1),rows.text(2),rows.text(5),std::move(parsed)});
        }catch(const Json::exception&){throw StorageError("game_settlement_pending_item_reward_invalid");}
    }
    transaction.commit();return result;
}

std::vector<GameSettlementOutbox> Storage::pending_game_settlements(const std::string& username,std::int64_t role) {
    const std::lock_guard lock(mutex_);
    if(profile_!=ClientProfile::richonline)throw StorageError("game_settlement_profile_invalid");
    Transaction transaction(db_);(void)owned_gold(db_,username,role);outbox_schema(db_);
    Statement rows(db_,"SELECT o.operation_id,o.match_id,o.delivery,o.next_message,o.message_count,p.request,p.result "
        "FROM game_settlement_outbox o JOIN operations p ON p.operation_id=o.operation_id "
        "WHERE o.role_id=? AND o.next_message<o.message_count ORDER BY o.rowid");
    rows.bind(1,role);std::vector<GameSettlementOutbox> result;
    while(rows.row()) {
        try {
            const auto request=Json::parse(rows.text(5));const auto name=request.at("outcome").get<std::string>();
            const auto outcome=name=="win"?GameOutcome::win:name=="loss"?GameOutcome::loss:GameOutcome::draw;
            if(name!="win" && name!="loss" && name!="draw")throw StorageError("game_settlement_outbox_invalid");
            const auto delivery_value=Json::parse(rows.text(2));
            if(request.at("delivery")!=delivery_value || request.at("username")!=username ||
                request.at("role_id")!=role || request.at("match_id")!=rows.text(1))
                throw StorageError("game_settlement_outbox_invalid");
            auto delivery=delivery_from_json(delivery_value,outcome);
            const auto expected=delivery.bankrupt_slots.size()*2+3;
            if(rows.integer(4)!=static_cast<std::int64_t>(expected) || rows.integer(3)<0 ||
                rows.integer(3)>=rows.integer(4))throw StorageError("game_settlement_outbox_invalid");
            result.push_back({rows.text(0),rows.text(1),outcome,std::move(delivery),
                result_from_json(Json::parse(rows.text(6))),static_cast<std::uint32_t>(rows.integer(3))});
        }catch(const Json::exception&){throw StorageError("game_settlement_outbox_invalid");}
    }
    transaction.commit();return result;
}

void Storage::advance_game_settlement_outbox(const std::string& username,std::int64_t role,
                                            const std::string& operation,std::uint32_t sent_message) {
    const std::lock_guard lock(mutex_);
    if(profile_!=ClientProfile::richonline)throw StorageError("game_settlement_profile_invalid");
    text(operation,256,"game_settlement_operation_invalid");
    Transaction transaction(db_);(void)owned_gold(db_,username,role);outbox_schema(db_);
    Statement row(db_,"SELECT next_message,message_count FROM game_settlement_outbox WHERE operation_id=? AND role_id=?");
    row.bind(1,operation);row.bind(2,role);
    if(!row.row())throw StorageError("game_settlement_outbox_missing");
    const auto cursor=row.integer(0),total=row.integer(1);
    if(sent_message>=total || sent_message>cursor)throw StorageError("game_settlement_outbox_sequence_invalid");
    if(sent_message==cursor) {
        Statement advance(db_,"UPDATE game_settlement_outbox SET next_message=next_message+1 WHERE operation_id=?");
        advance.bind(1,operation);advance.row();
    }
    transaction.commit();
}

std::vector<GameSettlementProfileRefresh> Storage::pending_game_settlement_profile_refreshes(
    const std::string& username,std::int64_t role) {
    const std::lock_guard lock(mutex_);
    if(profile_!=ClientProfile::richonline)throw StorageError("game_settlement_profile_invalid");
    Transaction transaction(db_);(void)owned_gold(db_,username,role);outbox_schema(db_);profile_refresh_schema(db_);
    Statement rows(db_,"SELECT r.operation_id FROM game_settlement_profile_refreshes r "
        "JOIN game_settlement_outbox b ON b.operation_id=r.operation_id "
        "WHERE r.role_id=? AND r.state='pending' AND b.next_message=b.message_count ORDER BY r.rowid");
    rows.bind(1,role);std::vector<GameSettlementProfileRefresh> result;
    while(rows.row())result.push_back(refresh_intent(db_,username,role,rows.text(0)));
    transaction.commit();return result;
}

GameSettlementProfileRefreshAttempt Storage::stage_game_settlement_profile_refresh(
    const std::string& username,std::int64_t role,const std::string& operation,
    std::uint32_t expected_actor,const std::string& generation,std::span<const std::uint8_t> profile) {
    const std::lock_guard lock(mutex_);
    if(profile_!=ClientProfile::richonline)throw StorageError("game_settlement_profile_invalid");
    text(operation,256,"game_settlement_operation_invalid");
    text(generation,256,"game_settlement_refresh_generation_invalid");validate_profile(profile,expected_actor);
    Transaction transaction(db_);outbox_schema(db_);profile_refresh_schema(db_);
    Statement owner(db_,"SELECT * FROM roles WHERE username=? AND role_id=?");owner.bind(1,username);owner.bind(2,role);
    if(!owner.row())throw StorageError("game_settlement_role_not_owned");
    const auto current=owner.record();
    for(const auto& [offset,field]:std::array<std::pair<std::size_t,const char*>,6>{{
        {24,"wins"},{28,"losses"},{32,"draws"},{52,"level"},{104,"experience"},{108,"escapes"}}}) {
        if(profile_u32(profile,offset)!=current.at(field).get<std::uint32_t>())
            throw StorageError("game_settlement_refresh_profile_stale");
    }
    if(profile_f64(profile,80)!=current.at("coins").get<double>() || profile_f64(profile,88)!=current.at("gold").get<double>())
        throw StorageError("game_settlement_refresh_profile_stale");
    auto intent=refresh_intent(db_,username,role,operation);
    Statement row(db_,"SELECT state,attempt FROM game_settlement_profile_refreshes WHERE operation_id=?");row.bind(1,operation);
    if(!row.row())throw StorageError("game_settlement_refresh_missing");
    if(row.text(0)!="pending")throw StorageError("game_settlement_refresh_already_delivered");
    const auto prior=row.integer(1);
    if(prior==std::numeric_limits<std::int64_t>::max())throw StorageError("game_settlement_refresh_attempt_overflow");
    GameSettlementProfileRefreshAttempt result{std::move(intent),generation,prior+1,{}};
    std::copy(profile.begin(),profile.end(),result.profile.begin());
    Statement stage(db_,"UPDATE game_settlement_profile_refreshes SET connection_generation=?,attempt=?,payload=? WHERE operation_id=?");
    stage.bind(1,generation);stage.bind(2,result.attempt);stage.bind(3,profile_json(profile));stage.bind(4,operation);stage.row();
    transaction.commit();return result;
}

bool Storage::confirm_game_settlement_profile_refresh(const std::string& username,std::int64_t role,
    const GameSettlementProfileRefreshAttempt& attempt,std::uint16_t type,std::span<const std::uint8_t> sent) {
    const std::lock_guard lock(mutex_);
    if(profile_!=ClientProfile::richonline)throw StorageError("game_settlement_profile_invalid");
    Transaction transaction(db_);(void)owned_gold(db_,username,role);outbox_schema(db_);profile_refresh_schema(db_);
    const auto intent=refresh_intent(db_,username,role,attempt.intent.operation_id);
    if(type!=19 || sent.size()!=144 || intent.role_id!=attempt.intent.role_id || intent.match_id!=attempt.intent.match_id ||
        !std::equal(sent.begin(),sent.end(),attempt.profile.begin()))return false;
    Statement row(db_,"SELECT state,connection_generation,attempt,payload FROM game_settlement_profile_refreshes WHERE operation_id=?");
    row.bind(1,intent.operation_id);
    if(!row.row() || row.text(0)!="pending" || row.text(1)!=attempt.connection_generation || row.integer(2)!=attempt.attempt ||
        row.text(3)!=profile_json(sent))return false;
    Statement confirm(db_,"UPDATE game_settlement_profile_refreshes SET state='confirmed' WHERE operation_id=?");
    confirm.bind(1,intent.operation_id);confirm.row();transaction.commit();return true;
}
}

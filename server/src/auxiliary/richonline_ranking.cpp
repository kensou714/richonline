#include "richonline_ranking.hpp"
#include "storage_detail.hpp"
#include "storage_achievement_detail.hpp"

#include <algorithm>
#include <cmath>
#include <limits>

namespace richnet {
using namespace storage_detail;
namespace {
bool achievement_category(std::int32_t category) {
    return category==1 || category==3 || category==9 || category==13 || category==15;
}
void open_ranking_database(sqlite3*& db,const std::filesystem::path& database,int flags) {
    const auto path=database.u8string();
    const auto result=sqlite3_open_v2(reinterpret_cast<const char*>(path.c_str()),&db,flags|SQLITE_OPEN_FULLMUTEX,nullptr);
    try {
        if(result!=SQLITE_OK)throw StorageError("ranking_database_open_failed");
        if(sqlite3_busy_timeout(db,5000)!=SQLITE_OK)throw StorageError("ranking_database_timeout_failed");
        Statement profile(db,"SELECT value FROM metadata WHERE key='client_profile'");
        if(!profile.row() || profile.text(0)!=client_profile_name(ClientProfile::richonline))
            throw StorageError("ranking_database_profile_mismatch");
    }catch(...){sqlite3_close(db);db=nullptr;throw;}
}
RichonlineAuxiliaryName role_name(const std::string& name) {
    const auto encoded=client_text(name,ClientProfile::richonline);
    if(encoded.empty() || encoded.size()>=32)throw StorageError("ranking_role_name_invalid");
    RichonlineAuxiliaryName result{};
    std::copy(encoded.begin(),encoded.end(),result.begin());return result;
}
RichonlineAuxiliaryName subject_name(const RichonlineAuxiliaryName& name) {
    const auto end=std::find(name.begin(),name.end(),0);
    if(end==name.begin())throw StorageError("ranking_subject_name_invalid");
    RichonlineAuxiliaryName result{};
    std::copy(name.begin(),end,result.begin());return result;
}
Bytes achievement_response(sqlite3* db,const RichonlineInquiryRequest& request) {
    if(!achievement_category(request.category))throw StorageError("ranking_category_unknown");
    Statement schema(db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='richonline_achievement_policies'");
    if(!schema.row())throw StorageError("ranking_achievement_statistics_not_integrated");
    Statement available(db,"SELECT policy FROM richonline_achievement_policies WHERE category=?");
    available.bind(1,request.category);
    if(!available.row())throw StorageError("ranking_achievement_category_not_recorded");
    const auto subject=subject_name(*request.name);
    Statement roles(db,"SELECT role_id,name FROM roles ORDER BY role_id");
    std::optional<std::int64_t> subject_role;
    while(roles.row()) {
        if(role_name(roles.text(1))!=subject)continue;
        if(subject_role)throw StorageError("ranking_subject_name_ambiguous");
        subject_role=roles.integer(0);
    }
    // The NEW search UI displays only ranks 1..10000; the visible table is 100.
    Statement scores(db,"WITH scores AS (SELECT r.role_id,r.name,SUM(a.score) AS score "
        "FROM richonline_achievement_matches a JOIN roles r ON r.role_id=a.role_id "
        "WHERE a.category=? GROUP BY r.role_id HAVING SUM(a.score)>0), "
        "ranked AS (SELECT *,ROW_NUMBER() OVER(ORDER BY score DESC,role_id ASC) AS ordinal FROM scores) "
        "SELECT name,score,ordinal,role_id FROM ranked WHERE ordinal<=100 OR role_id=? ORDER BY ordinal");
    scores.bind(1,request.category);
    scores.bind(2,subject_role.value_or(-1));
    std::vector<RichonlineRankValue> rows;
    RichonlineRankValue self{subject,0};
    std::int32_t rank=-1;
    while(scores.row()) {
        const auto score=scores.integer(1);
        if(score<0 || score>std::numeric_limits<std::int32_t>::max())
            throw StorageError("ranking_achievement_score_out_of_wire_range");
        RichonlineRankValue row{role_name(scores.text(0)),static_cast<std::int32_t>(score)};
        const auto ordinal=scores.integer(2);
        if(subject_role && scores.integer(3)==*subject_role) {
            if(ordinal<=10000)rank=static_cast<std::int32_t>(ordinal);
            self=row;
        }
        if(ordinal<=100)rows.push_back(row);
    }
    if(request.type==RichonlineInquiryType::search_rank)return encode_richonline_rank_search(rank);
    return encode_richonline_named_ranking(rank,self,rows);
}
std::int32_t integer_column(const nlohmann::json& role, const char* field) {
    const auto value = role.at(field).get<std::int64_t>();
    if (value < 0 || value > std::numeric_limits<std::int32_t>::max())
        throw StorageError("ranking_stored_integer_out_of_wire_range");
    return static_cast<std::int32_t>(value);
}
RichonlineRankColumns account_row(const nlohmann::json& role) {
    const auto name = client_text(role.at("name").get<std::string>(), ClientProfile::richonline);
    if (name.empty() || name.size() >= 32) throw StorageError("ranking_role_name_invalid");
    RichonlineAuxiliaryName wire_name{};
    std::copy(name.begin(), name.end(), wire_name.begin());
    const auto gold = role.at("gold").get<double>();
    // NEW ranking has an integer gold column. Fractional account balances remain
    // exact in SQLite and sort by their full value; this display shows whole beans.
    if (!std::isfinite(gold) || gold < 0 || std::floor(gold) > std::numeric_limits<std::int32_t>::max())
        throw StorageError("ranking_gold_out_of_wire_range");
    return {wire_name, {integer_column(role, "wins"), integer_column(role, "level"),
        static_cast<std::int32_t>(std::floor(gold))}};
}
}

RichonlineRankingStore::RichonlineRankingStore(const std::filesystem::path& database) {
    open_ranking_database(db_,database,SQLITE_OPEN_READONLY);
}
RichonlineRankingStore::~RichonlineRankingStore() { sqlite3_close(db_); }

std::optional<Bytes> RichonlineRankingStore::response(View input) {
    const auto request = decode_richonline_inquiry_request(input);
    if (!request) return std::nullopt;
    if (request->type != RichonlineInquiryType::category_table) {
        const std::lock_guard lock(mutex_);
        Transaction transaction(db_,false);
        auto result=achievement_response(db_,*request);
        transaction.commit();return result;
    }
    const char* query = nullptr;
    switch (static_cast<RichonlineAccountRanking>(request->category)) {
    case RichonlineAccountRanking::wins:
        query = "SELECT name,wins,level,gold FROM roles ORDER BY wins DESC,role_id ASC LIMIT 100"; break;
    case RichonlineAccountRanking::level:
        query = "SELECT name,wins,level,gold FROM roles ORDER BY level DESC,role_id ASC LIMIT 100"; break;
    case RichonlineAccountRanking::gold:
        query = "SELECT name,wins,level,gold FROM roles ORDER BY gold DESC,role_id ASC LIMIT 100"; break;
    default: throw StorageError("ranking_category_unknown");
    }
    const std::lock_guard lock(mutex_);
    Transaction transaction(db_, false);
    Statement rows(db_, query);
    std::vector<RichonlineRankColumns> result;
    while (rows.row()) result.push_back(account_row(rows.record()));
    transaction.commit();
    return encode_richonline_category_ranking(result);
}

RichonlineAchievementStore::RichonlineAchievementStore(const std::filesystem::path& database) {
    open_ranking_database(db_,database,SQLITE_OPEN_READWRITE);
    try {
        execute(db_,"PRAGMA foreign_keys=ON");
        Transaction transaction(db_);
        richonline_achievement_schema(db_);
        transaction.commit();
    }catch(...){sqlite3_close(db_);db_=nullptr;throw;}
}
RichonlineAchievementStore::~RichonlineAchievementStore(){sqlite3_close(db_);}
bool RichonlineAchievementStore::record_match(const std::string& username,std::int64_t role_id,
    const std::string& match_id,RichonlineAchievement category,std::uint64_t score,const std::string& policy) {
    const GameSettlementAchievement value{category,score,policy,{}};
    validate_richonline_achievement(value);
    if(match_id.empty() || match_id.size()>256 || match_id.find('\0')!=std::string::npos)
        throw StorageError("ranking_achievement_identity_invalid");
    const std::lock_guard lock(mutex_);Transaction transaction(db_);
    Statement owner(db_,"SELECT 1 FROM roles WHERE username=? AND role_id=?");
    owner.bind(1,username);owner.bind(2,role_id);
    if(!owner.row())throw StorageError("ranking_achievement_role_not_owned");
    Statement settlement(db_,"SELECT operation_id,request FROM operations WHERE role_id=? "
        "AND source='native-game-settlement' AND json_extract(request,'$.match_id')=? "
        "AND json_extract(request,'$.username')=?");
    settlement.bind(1,role_id);settlement.bind(2,match_id);settlement.bind(3,username);
    if(!settlement.row())throw StorageError("ranking_achievement_match_not_settled");
    const auto operation=settlement.text(0);
    const auto canonical=nlohmann::json::parse(settlement.text(1));
    if(settlement.row())throw StorageError("ranking_achievement_match_ambiguous");
    if(canonical.contains("achievement") && canonical.at("achievement").at("category")==static_cast<std::int32_t>(category)) {
        const auto& saved=canonical.at("achievement");
        if(saved.at("score")!=score || saved.at("policy")!=policy)
            throw StorageError("ranking_achievement_replay_conflict");
        verify_richonline_achievement(db_,role_id,match_id,operation,value);
        transaction.commit();return false;
    }
    const auto inserted=insert_richonline_achievement(db_,role_id,match_id,operation,value);
    transaction.commit();return inserted;
}
}

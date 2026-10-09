#include "richonline_social.hpp"
#include "richonline_lobby_error.hpp"
#include "storage_detail.hpp"
#include <windows.h>
#include <algorithm>

namespace richnet {
using namespace storage_detail;
namespace {
Bytes text32(View bytes,bool nonempty=false) {
    if(bytes.size()!=32) throw CodecError("social_text_length_invalid");
    const auto end=std::find(bytes.begin(),bytes.end(),0);
    if(end==bytes.end() || (nonempty&&end==bytes.begin())) throw CodecError("social_text_termination_invalid");
    const auto length=static_cast<int>(end-bytes.begin());
    if(length!=0 && MultiByteToWideChar(950,MB_ERR_INVALID_CHARS,
        reinterpret_cast<const char*>(bytes.data()),length,nullptr,0)==0)
        throw CodecError("social_text_big5_invalid");
    Bytes result(bytes.begin(),end);result.resize(32,0);return result;
}
Bytes name32(View name) {Bytes result(name.begin(),name.end());result.resize(32,0);return result;}
Frame actor_frame(std::uint32_t wire,std::uint32_t actor) {Bytes data;append_le(data,actor,4);return {wire,std::move(data)};}
std::int64_t unix_now() {return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();}
void audit(sqlite3* db,std::uint32_t role_id,const std::string& username,std::uint32_t other,bool added) {
    Statement event(db,"INSERT INTO audit(role_id,username,field,old_value,new_value,source,reason,operation_id) VALUES(?,?,'friendship',?,?,'native-social',?,'')");
    event.bind(1,role_id);event.bind(2,username);event.bind(3,added?"absent":"present");event.bind(4,added?"present":"absent");
    event.bind(5,std::string(added?"accepted role ":"removed role ")+std::to_string(other));event.row();
}
}

RichonlineSocial::RichonlineSocial(Storage& storage,const BootstrapBlobs& blobs,std::uint32_t server_id)
    :storage_(storage),blobs_(blobs),server_id_(server_id) {
    const auto path=storage.database_path().u8string();
    const auto status=sqlite3_open_v2(reinterpret_cast<const char*>(path.c_str()),&db_,SQLITE_OPEN_READWRITE|SQLITE_OPEN_FULLMUTEX,nullptr);
    try {
        if(status!=SQLITE_OK) throw StorageError("social_database_open_failed");
        if(sqlite3_busy_timeout(db_,5000)!=SQLITE_OK) throw StorageError("social_database_timeout_failed");
        execute(db_,"PRAGMA foreign_keys=ON");
        Transaction transaction(db_);
        Statement profile(db_,"SELECT value FROM metadata WHERE key='client_profile'");
        if(!profile.row()||profile.text(0)!="richonline") throw StorageError("social_database_profile_mismatch");
        execute(db_,R"sql(CREATE TABLE IF NOT EXISTS role_friendships(
 role_low INTEGER NOT NULL REFERENCES roles(role_id),
 role_high INTEGER NOT NULL REFERENCES roles(role_id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(role_low,role_high),CHECK(role_low<role_high)) STRICT;)sql");
        transaction.commit();
    } catch(...) {sqlite3_close(db_);db_=nullptr;throw;}
}
RichonlineSocial::~RichonlineSocial(){sqlite3_close(db_);}
LobbyRole RichonlineSocial::role(std::uint32_t actor,const std::optional<std::string>& username) {
    Statement query(db_,"SELECT * FROM roles WHERE role_id=?");query.bind(1,actor);
    if(!query.row()) throw StorageError("social_role_missing");
    const auto record=query.record();
    if(username&&record.at("username")!=*username) throw StorageError("social_role_not_owned");
    return parse_lobby_role(record);
}
std::vector<std::uint32_t> RichonlineSocial::friends(std::uint32_t actor) {
    Statement query(db_,"SELECT CASE WHEN role_low=? THEN role_high ELSE role_low END AS friend_id FROM role_friendships WHERE role_low=? OR role_high=? ORDER BY friend_id");
    for(int i=1;i<=3;++i) query.bind(i,actor);
    std::vector<std::uint32_t> result;while(query.row())result.push_back(static_cast<std::uint32_t>(query.integer(0)));
    if(result.size()>100)throw StorageError("social_friend_capacity_exceeded");return result;
}
Frame RichonlineSocial::presence(const Peer& peer,bool online) const {
    Bytes data;append_le(data,server_id_,4);append_le(data,peer.channel,4);
    const auto name=name32(peer.name);data.insert(data.end(),name.begin(),name.end());return {online?61U:62U,std::move(data)};
}
std::vector<RichonlineRoomDispatch> RichonlineSocial::enter(std::uint64_t connection,const std::string& username,std::uint32_t actor,std::uint32_t channel) {
    if(peers_.contains(connection))throw CodecError("social_peer_already_entered");
    for(const auto& [id,peer]:peers_){static_cast<void>(id);if(peer.role_id==actor)throw CodecError("social_actor_already_online");}
    const auto own=role(actor,username);Peer peer{username,actor,channel,own.name};
    const auto ids=friends(actor);Bytes list;append_le(list,static_cast<std::uint32_t>(ids.size()),4);
    for(const auto id:ids){const auto encoded=encode_lobby_role_record(role(id),blobs_,storage_.lobby_inventory_for_role(id,unix_now()));list.insert(list.end(),encoded.begin(),encoded.end());}
    std::vector<RichonlineRoomDispatch> output{{connection,{69,std::move(list)}}};
    for(const auto& [id,other]:peers_)if(std::find(ids.begin(),ids.end(),other.role_id)!=ids.end()){
        output.push_back({connection,presence(other,true)});output.push_back({id,presence(peer,true)});
    }
    peers_.emplace(connection,std::move(peer));return output;
}
std::vector<RichonlineRoomDispatch> RichonlineSocial::leave(std::uint64_t connection) {
    std::erase_if(invitations_,[&](const auto& entry){return entry.first.first==connection||entry.first.second==connection;});
    const auto peer=peers_.find(connection);if(peer==peers_.end())return {};
    // Remove the live session even if the database is unavailable during cleanup.
    const auto departed=peer->second;peers_.erase(peer);
    const auto ids=friends(departed.role_id);std::vector<RichonlineRoomDispatch> output;
    for(const auto& [id,other]:peers_)if(std::find(ids.begin(),ids.end(),other.role_id)!=ids.end())output.push_back({id,presence(departed,false)});
    return output;
}
RichonlineSocialResult RichonlineSocial::receive(std::uint64_t connection,const Frame& request) {
    try {
        if(request.wire_type<28||request.wire_type>31)throw CodecError("social_wire_invalid");
        const auto own=peers_.find(connection);if(own==peers_.end())throw CodecError("social_channel_required");
        const auto& peer=own->second;static_cast<void>(role(peer.role_id,peer.username));
        const auto now=std::chrono::steady_clock::now();
        std::erase_if(invitations_,[&](const auto& entry){return entry.second<=now;});
        const auto expected=request.wire_type==28?36U:request.wire_type==29?40U:request.wire_type==30?4U:32U;
        if(request.payload.size()!=expected)throw CodecError("social_request_length_invalid");
        if(request.wire_type==31){
            const auto name=text32(request.payload,true);const auto ids=friends(peer.role_id);
            std::optional<LobbyRole> target;
            for(const auto id:ids){auto item=role(id);if(name32(item.name)==name){if(target)throw CodecError("social_friend_name_ambiguous");target=std::move(item);}}
            if(!target)throw CodecError("social_friend_missing");
            Transaction transaction(db_);Statement erase(db_,"DELETE FROM role_friendships WHERE role_low=? AND role_high=?");
            erase.bind(1,std::min(peer.role_id,target->id));erase.bind(2,std::max(peer.role_id,target->id));erase.row();
            audit(db_,peer.role_id,peer.username,target->id,false);transaction.commit();
            std::vector<RichonlineRoomDispatch> output{{connection,{211,name}}};
            for(const auto& [id,other]:peers_)if(other.role_id==target->id)output.push_back({id,{211,name32(peer.name)}});
            return {std::move(output),{}};
        }
        const auto actor=read_le(View(request.payload).first(4));
        const auto target=std::find_if(peers_.begin(),peers_.end(),[&](const auto& item){return item.second.role_id==actor&&item.second.channel==peer.channel;});
        if(target==peers_.end()||target->first==connection)throw CodecError("social_target_unavailable");
        if(request.wire_type==28){
            const auto message=text32(View(request.payload).subspan(4,32));const auto ids=friends(peer.role_id);
            if(std::find(ids.begin(),ids.end(),actor)!=ids.end())throw CodecError("social_already_friends");
            if(ids.size()>=100||friends(actor).size()>=100)throw CodecError("social_friend_capacity_exceeded");
            const Pair key{connection,target->first};if(invitations_.contains(key))throw CodecError("social_invitation_pending");
            const auto pending=std::count_if(invitations_.begin(),invitations_.end(),[&](const auto& item){return item.first.first==connection;});
            if(pending>=100)throw CodecError("social_invitation_capacity_exceeded");
            invitations_.emplace(key,now+std::chrono::minutes(5));auto invitation=actor_frame(63,peer.role_id);
            invitation.payload.insert(invitation.payload.end(),message.begin(),message.end());return {{{target->first,std::move(invitation)}},{}};
        }
        const Pair key{target->first,connection};if(!invitations_.contains(key))throw CodecError("social_invitation_missing_or_expired");
        if(request.wire_type==29){
            const auto message=text32(View(request.payload).subspan(4,32));
            const auto text_end=std::find(message.begin(),message.end(),0);
            if(read_le(View(request.payload).subspan(36,4))!=static_cast<std::uint32_t>(text_end-message.begin()+1))throw CodecError("social_decline_length_invalid");
            auto declined=actor_frame(210,peer.role_id);declined.payload.insert(declined.payload.end(),message.begin(),message.end());invitations_.erase(key);
            return {{{target->first,std::move(declined)}},{}};
        }
        Transaction transaction(db_);const auto ids=friends(peer.role_id);
        if(std::find(ids.begin(),ids.end(),actor)!=ids.end())throw CodecError("social_already_friends");
        if(ids.size()>=100||friends(actor).size()>=100)throw CodecError("social_friend_capacity_exceeded");
        Statement insert(db_,"INSERT INTO role_friendships(role_low,role_high) VALUES(?,?)");insert.bind(1,std::min(actor,peer.role_id));insert.bind(2,std::max(actor,peer.role_id));insert.row();
        audit(db_,peer.role_id,peer.username,actor,true);transaction.commit();
        invitations_.erase(key);invitations_.erase({connection,target->first});
        return {{{connection,actor_frame(209,actor)},{connection,presence(target->second,true)},
            {target->first,actor_frame(209,peer.role_id)},{target->first,presence(peer,true)}},{}};
    } catch(const std::runtime_error& error) {
        return {{{connection,richonline_lobby_failure(request.wire_type,-1)}},error.what()};
    }
}
}

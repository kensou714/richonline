#include "server_lobby_adapter.hpp"
#include "lua_lobby.hpp"
#include "richonline_room_directory.hpp"
#include "richonline_lobby_chat.hpp"
#include "richonline_lobby_error.hpp"
#include "richonline_intro_request.hpp"
#include "richonline_social.hpp"
#include "richonline_mail_service.hpp"
#include "richonline_lobby_membership.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <bit>
#include <chrono>
#include <limits>
#include <mutex>
#include <string_view>
#include <utility>

namespace richnet {
namespace {
void write_profile_u32(Bytes& bytes,std::size_t offset,std::uint32_t value) {
    for(std::size_t i=0;i<4;++i) bytes.at(offset+i)=static_cast<std::uint8_t>(value>>(8*i));
}
void write_profile_f64(Bytes& bytes,std::size_t offset,double value) {
    const auto bits=std::bit_cast<std::uint64_t>(value);
    for(std::size_t i=0;i<8;++i) bytes.at(offset+i)=static_cast<std::uint8_t>(bits>>(8*i));
}
}
struct ServerLobbyAdapter::Connections {
    struct Peer {
        std::string username;
        std::uint64_t mail_sequence=0;
        std::optional<std::uint32_t> selected_role;
        std::optional<std::uint32_t> actor;
        std::optional<std::uint32_t> channel;
        std::unique_ptr<RichonlineMallService> mall;
        std::uint64_t mall_generation=0;
        std::optional<GameSettlementProfileRefreshAttempt> profile_attempt;
        std::vector<Frame> outbound;
        std::size_t outbound_bytes = 0;
        bool overflowed = false;
        std::vector<Frame> drain() {
            if (overflowed) throw CodecError("richonline_peer_outbound_capacity_exceeded");
            outbound_bytes = 0;
            return std::exchange(outbound, {});
        }
    };
    std::mutex mutex;
    std::uint64_t next = 1;
    std::map<std::uint64_t, Peer> peers;
    std::map<std::uint32_t, RichonlineRoomDirectory> rooms;
    std::unique_ptr<RichonlineAuxiliaryStore> introductions;
    std::unique_ptr<RichonlineSocial> social;
    std::string mail_namespace;
    Connections() {
        std::array<std::uint8_t,16> random{};
        if(BCryptGenRandom(nullptr,random.data(),static_cast<ULONG>(random.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0)
            throw CodecError("richonline_mail_operation_namespace_failed");
        constexpr char digits[]="0123456789abcdef";mail_namespace.reserve(random.size()*2);
        for(const auto byte:random){mail_namespace.push_back(digits[byte>>4]);mail_namespace.push_back(digits[byte&15]);}
    }
    RichonlineRoomDirectory* directory(std::uint64_t connection) {
        const auto peer=peers.find(connection);
        if (peer==peers.end() || !peer->second.channel) return nullptr;
        const auto found=rooms.find(*peer->second.channel);
        return found==rooms.end() ? nullptr : &found->second;
    }
    void deliver(std::vector<RichonlineRoomDispatch> messages) {
        for (auto& message : messages) {
            const auto peer = peers.find(message.recipient);
            if (peer == peers.end() || peer->second.overflowed) continue;
            auto& destination = peer->second;
            const auto bytes = message.frame.payload.size() + 8;
            if (destination.outbound.size() >= 4096 || destination.outbound_bytes + bytes > 4U * max_frame_total) {
                destination.overflowed = true;
                destination.outbound.clear();
                destination.outbound_bytes = 0;
                continue;
            }
            destination.outbound_bytes += bytes;
            destination.outbound.push_back(std::move(message.frame));
        }
    }
};

void ServerLobbyAdapter::queue_pending_profile_refreshes(std::uint64_t connection) {
    // The caller holds Connections::mutex, which also serializes lobby account
    // mutations and observer-cache updates for this connection.
    auto& peer=connections_->peers.at(connection);
    if(!peer.actor||!peer.selected_role||!peer.channel||peer.profile_attempt) return;
    const auto pending=storage_.pending_game_settlement_profile_refreshes(peer.username,*peer.selected_role);
    if(pending.empty()) return;
    auto* directory=connections_->directory(connection);
    if(!directory) {
        if(log_) log_("richonline_postgame_profile_deferred",{{"connection",connection},
            {"role_id",*peer.selected_role},{"operation_id",pending.front().operation_id},
            {"reason","room_directory_unavailable"}});
        return;
    }
    const auto current=directory->current_profile(connection,*peer.actor);
    auto profile=current.payload;
    profile.resize(144);
    const auto generation=connections_->mail_namespace+":"+std::to_string(connection);
    std::optional<GameSettlementProfileRefreshAttempt> attempt;
    for(unsigned retry=0;retry<3;++retry) {
        try {
            const auto records=storage_.roles_for_username(peer.username);
            const auto found=std::find_if(records.begin(),records.end(),[&](const auto& record) {
                return record.at("role_id").template get<std::uint32_t>()==*peer.selected_role;
            });
            if(found==records.end()) throw CodecError("richonline_postgame_profile_role_missing");
            const auto role=parse_lobby_role(*found);
            write_profile_u32(profile,24,role.wins);
            write_profile_u32(profile,28,role.losses);
            write_profile_u32(profile,32,role.draws);
            write_profile_u32(profile,52,role.level);
            write_profile_f64(profile,80,role.coins);
            write_profile_f64(profile,88,role.gold);
            write_profile_u32(profile,104,role.experience);
            write_profile_u32(profile,108,role.escapes);
            attempt=storage_.stage_game_settlement_profile_refresh(peer.username,*peer.selected_role,
                pending.front().operation_id,*peer.actor,generation,profile);
            break;
        } catch(const StorageError& error) {
            if(log_) log_("richonline_postgame_profile_deferred",{{"connection",connection},
                {"role_id",*peer.selected_role},{"operation_id",pending.front().operation_id},
                {"reason",error.what()},{"attempt",retry+1}});
            if(std::string_view(error.what())!="game_settlement_refresh_profile_stale") return;
        }
    }
    if(!attempt) return;
    Frame update{19,Bytes(attempt->profile.begin(),attempt->profile.end())};
    directory->refresh_profile(connection,*peer.actor,current,update);
    peer.profile_attempt=*attempt;
    std::vector<RichonlineRoomDispatch> deliveries;
    for(const auto& [recipient,observer]:connections_->peers)
        if(observer.channel==peer.channel && observer.actor)
            deliveries.push_back({recipient,update});
    connections_->deliver(std::move(deliveries));
    if(log_) log_("richonline_postgame_profile_queued",{{"connection",connection},
        {"role_id",*peer.selected_role},{"wire_actor",*peer.actor},
        {"operation_id",attempt->intent.operation_id},{"attempt",attempt->attempt}});
}

void ServerLobbyAdapter::set_game_registry(std::shared_ptr<RichonlineGameRegistry> registry) {
    if (connections_) throw CodecError("richonline_game_registry_set_after_listening");
    game_registry_ = std::move(registry);
}

void ServerLobbyAdapter::set_mall_catalog(std::shared_ptr<const RichonlineMallCatalog> catalog) {
    if(connections_) throw CodecError("richonline_mall_catalog_set_after_listening");
    if(!catalog||catalog->products().empty()||catalog->offers().empty()) throw CodecError("richonline_mall_catalog_empty");
    mall_catalog_=std::move(catalog);
}

std::uint32_t ServerLobbyAdapter::channel_player_count(std::uint32_t channel) const {
    if (!connections_) return 0;
    const std::lock_guard guard(connections_->mutex);
    std::uint32_t count=0;
    for (const auto& [id,peer]:connections_->peers) {
        static_cast<void>(id);
        if (peer.channel==channel && peer.actor) ++count;
    }
    return count;
}

LobbyCallbacks ServerLobbyAdapter::callbacks() {
    if (!connections_) {
        connections_ = std::make_shared<Connections>();
        if(blobs_.social_server_id) connections_->social=std::make_unique<RichonlineSocial>(storage_,blobs_,*blobs_.social_server_id);
        if (blobs_.room_unknown_prefix) {
            const auto add=[&](std::uint32_t channel,std::uint32_t capacity) {
                connections_->rooms.try_emplace(channel,RichonlineRoomPolicy{*blobs_.room_unknown_prefix,capacity},
                    [this,channel](const std::string& message) { if (log_) log_("richonline_room_state", {{"channel",channel},{"detail", message}}); });
            };
            if (blobs_.channels.empty()) add(0,blobs_.game_capacity);
            else for (const auto& channel:blobs_.channels) add(channel.key,channel.room_capacity);
        }
    }
    const auto connections = connections_;
    const std::lock_guard lock(connections->mutex);
    const auto connection = connections->next++;
    connections->peers.emplace(connection, Connections::Peer{});
    LobbyCallbacks result;
    result.verify_credentials = [this, connection](const std::string& username, View password) {
        const auto outcome = storage_.login(username, password);
        const char* category = nullptr;
        bool accepted = false;
        switch (outcome) {
        case LoginOutcome::authenticated: category = "authenticated"; accepted = true; break;
        case LoginOutcome::registered: category = "registered"; accepted = true; break;
        case LoginOutcome::registration_disabled: category = "registration_disabled"; break;
        case LoginOutcome::invalid_credentials: category = "invalid_credentials"; break;
        case LoginOutcome::password_mismatch: category = "password_mismatch"; break;
        }
        if (log_) log_("lobby_login_outcome", {{"connection", connection}, {"outcome", category}});
        return accepted;
    };
    result.login_responses = [this](const LobbyLogin& login) { return login_responses(login); };
    result.authenticated_request = [this, connections, connection](const LobbyLogin& login, const Frame& frame) {
        const std::lock_guard guard(connections->mutex);
        auto& peer = connections->peers.at(connection);
        try {
            if (frame.wire_type == 34) {
                auto output = authenticated_request(login, frame);
                if (peer.actor) throw CodecError("richonline_channel_already_entered");
                peer.mall.reset();
                peer.selected_role = read_le(frame.payload);
                peer.username=login.username_utf8;
                return output;
            }
            if (frame.wire_type == 7) {
                if (frame.payload.size() != 4) throw CodecError("richonline_channel_selection_length_invalid");
                const auto channel=read_le(frame.payload);
                if (channel >= (blobs_.channels.empty() ? 1 : blobs_.channels.size())) throw CodecError("richonline_channel_not_in_catalog");
                if (!peer.selected_role) throw CodecError("richonline_role_selection_required");
                if (peer.actor) throw CodecError("richonline_channel_already_entered");
                const auto actor = *peer.selected_role;
                for (const auto& [id,other]:connections->peers)
                    if (id!=connection && other.actor==actor) throw CodecError("richonline_actor_already_online_or_invalid");
                auto output = channel_responses(login, actor, channel);
                const auto rooms=connections->rooms.find(channel);
                if (rooms!=connections->rooms.end()) connections->deliver(rooms->second.enter(connection, actor, output.at(1)));
                peer.actor = actor;
                peer.channel = channel;
                if(connections->social) connections->deliver(connections->social->enter(connection,login.username_utf8,actor,channel));
                queue_pending_profile_refreshes(connection);
                auto pending = peer.drain();
                output.insert(output.end()-1, std::make_move_iterator(pending.begin()), std::make_move_iterator(pending.end()));
                return output;
            }
            if(frame.wire_type==8) {
                decode_richonline_leave_channel8(frame);
                if(!peer.actor||!peer.channel) throw CodecError("richonline_channel_selection_required");
                auto* directory=connections->directory(connection);
                if(!directory) throw CodecError("richonline_room_policy_not_configured");
                // The channel selector cannot own an admitted game. A late
                // channel-exit request must not silently cancel other players.
                if(directory->game_pending(connection)) throw CodecError("richonline_channel_leave_during_game");
                if(connections->social) connections->deliver(connections->social->leave(connection));
                connections->deliver(directory->disconnect(connection));
                peer.actor.reset();
                peer.channel.reset();
                peer.mall.reset();
                peer.profile_attempt.reset();
                // These belong to the cache cleared by NEW887150. Unconfirmed
                // settlement refresh intents remain durable for the next entry.
                peer.outbound.clear();
                peer.outbound_bytes=0;
                if(log_) log_("richonline_channel_left",{{"connection",connection},{"authenticated",true}});
                return std::vector<Frame>{encode_richonline_left_channel16()};
            }
            if (frame.wire_type == 42 || frame.wire_type == 61 || frame.wire_type == 62 ||
                frame.wire_type == 48 || frame.wire_type == 49 || frame.wire_type == 56) {
                if (!peer.selected_role) throw CodecError("richonline_role_selection_required");
                return account_request(login, *peer.selected_role, frame);
            }
            if(frame.wire_type==16||frame.wire_type==18||frame.wire_type==63) {
                const auto log_mall=[&](const std::string& reason,std::size_t frames) {
                    if(!log_) return;
                    nlohmann::json detail{{"connection",connection},{"wire_type",frame.wire_type},
                        {"payload_bytes",frame.payload.size()},{"diagnostic",reason},{"response_frames",frames},{"lobby_preserved",true}};
                    if((frame.wire_type==18 && frame.payload.size()==16) || (frame.wire_type==63 && frame.payload.size()==8)) {
                        const auto offset=frame.wire_type==18 ? 8U : 4U;
                        const auto key=read_le(View(frame.payload).subspan(offset,4));
                        detail["item_key"]=key;detail["product"]=key&4095U;
                        detail["currency"]=frame.wire_type==18 ? (key>>12U)&15U : read_le(View(frame.payload).first(4));
                    }
                    if(blobs_.richonline_mall_policy)
                        detail["date_epoch"]=static_cast<std::uint16_t>(blobs_.richonline_mall_policy->date_version);
                    log_("richonline_mall_operation",detail);
                };
                const auto refused=blobs_.richonline_mall_policy?blobs_.richonline_mall_policy->refused:-13;
                const auto reject=[&](const std::string& reason) {
                    // NEW16 is a one-way selection, with no verified result callback.
                    std::vector<Frame> output;
                    if(frame.wire_type!=16) output.push_back(richonline_lobby_failure(frame.wire_type,refused));
                    log_mall(reason,output.size());return output;
                };
                if(!peer.selected_role) return reject("mall_role_selection_required");
                if(!peer.actor) return reject("mall_channel_selection_required");
                if(!blobs_.richonline_mall_policy) return reject("mall_compatibility_policy_not_configured");
                if(!mall_catalog_) return reject("mall_catalog_not_configured");
                try {
                    if(!peer.mall) {
                        if(peer.mall_generation==std::numeric_limits<std::uint64_t>::max()) throw CodecError("mall_session_generation_exhausted");
                        peer.mall=std::make_unique<RichonlineMallService>(*mall_catalog_,
                            "lobby-mall:"+connections->mail_namespace+":"+std::to_string(connection)+":"+std::to_string(++peer.mall_generation),
                            *blobs_.richonline_mall_policy);
                    }
                    const auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                    auto reply=peer.mall->request(storage_,login.username_utf8,*peer.selected_role,frame,now);
                    if(!reply) throw CodecError("mall_service_wire_not_routed");
                    if(reply->role_refresh) {
                        auto refresh=profile_refresh(login.username_utf8,*peer.selected_role,*reply->role_refresh);
                        if(reply->role_refresh_after_frames) reply->frames.push_back(std::move(refresh));
                        else reply->frames.insert(reply->frames.begin(),std::move(refresh));
                    }
                    log_mall(reply->diagnostic,reply->frames.size());return std::move(reply->frames);
                } catch(const StorageError& error) {return reject(error.what());}
                  catch(const CodecError& error) {return reject(error.what());}
            }
            if(frame.wire_type==46) {
                if(!peer.selected_role||!blobs_.richonline_mail_policy||peer.mail_sequence==std::numeric_limits<std::uint64_t>::max()) {
                    const char* reason=!peer.selected_role?"mail_role_selection_required":!blobs_.richonline_mail_policy?
                        "mail_metadata_policy_not_configured":"mail_session_sequence_exhausted";
                    if(log_) log_("richonline_mail_operation",{{"connection",connection},{"wire_type",46},
                        {"payload_bytes",frame.payload.size()},{"diagnostic",reason}});
                    return std::vector<Frame>{richonline_lobby_failure(46,-112)};
                }
                const auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                const auto operation="lobby-mail:"+connections->mail_namespace+":"+std::to_string(connection)+":"+std::to_string(++peer.mail_sequence);
                auto mail=richonline_mail_send_request(storage_,login.username_utf8,*peer.selected_role,frame,now,operation,
                    {0,-112},blobs_.richonline_mail_policy->metadata);
                std::vector<RichonlineRoomDispatch> deliveries;
                if(mail.recipient) for(const auto& [id,other]:connections->peers)
                    if(other.actor&&other.username==mail.recipient->username&&static_cast<std::int64_t>(*other.actor)==mail.recipient->role_id)
                        deliveries.push_back({id,mail.recipient->frame});
                if(log_) log_("richonline_mail_operation",{{"connection",connection},{"wire_type",46},
                    {"payload_bytes",frame.payload.size()},{"diagnostic",mail.diagnostic},{"online_recipients",deliveries.size()}});
                connections->deliver(std::move(deliveries));return std::move(mail.frames);
            }
            if (frame.wire_type == 50) {
                if (!peer.selected_role) return std::vector<Frame>{richonline_lobby_failure(50,-1)};
                try {
                    if (!connections->introductions)
                        connections->introductions=std::make_unique<RichonlineAuxiliaryStore>(storage_.database_path());
                    auto result=richonline_intro_request(storage_,*connections->introductions,
                        login.username_utf8,*peer.selected_role,frame);
                    if (log_) log_("richonline_intro_save",{{"connection",connection},{"wire_type",50},
                        {"payload_bytes",frame.payload.size()},{"success",result.rejection.empty()},
                        {"reason",result.rejection}});
                    return result.responses;
                } catch (const std::runtime_error& error) {
                    if (log_) log_("richonline_intro_save",{{"connection",connection},{"wire_type",50},
                        {"payload_bytes",frame.payload.size()},{"success",false},{"reason",error.what()}});
                    return std::vector<Frame>{richonline_lobby_failure(50,-1)};
                }
            }
            if(frame.wire_type>=28 && frame.wire_type<=31) {
                if(!connections->social) return std::vector<Frame>{richonline_lobby_failure(frame.wire_type,-1)};
                auto social=connections->social->receive(connection,frame);
                if(log_) log_("richonline_social_operation",{{"connection",connection},{"wire_type",frame.wire_type},
                    {"payload_bytes",frame.payload.size()},{"success",social.rejection.empty()},{"reason",social.rejection},
                    {"recipients",social.deliveries.size()}});
                connections->deliver(std::move(social.deliveries));return peer.drain();
            }
            if (frame.wire_type == 15) {
                std::vector<RichonlineChatPeer> snapshot;
                for (const auto& [id,other]:connections->peers) {
                    if (!other.actor || !other.channel) continue;
                    auto* directory=connections->directory(id);
                    snapshot.push_back({id,*other.actor,*other.channel,
                        directory ? directory->room_key(id) : std::nullopt});
                }
                auto result=richonline_lobby_chat(connection,frame,snapshot);
                if (!result.rejection.empty()) {
                    if (log_) log_("richonline_chat_rejected",{{"connection",connection},
                        {"wire_type",15},{"payload_bytes",frame.payload.size()},
                        {"reason",result.rejection},{"lobby_preserved",true}});
                    // -1 is our generic refusal policy, not a recovered native
                    // chat enum. 82E9C0 accepts any status and clears pending15.
                    return std::vector<Frame>{richonline_lobby_failure(15,-1)};
                }
                if (log_) log_("richonline_chat_delivered",{{"connection",connection},
                    {"wire_type",15},{"payload_bytes",frame.payload.size()},
                    {"recipients",result.deliveries.size()}});
                connections->deliver(std::move(result.deliveries));
                return peer.drain();
            }
            switch (frame.wire_type) {
            case 3: case 4: case 5: case 6: case 9: case 10: case 23: case 27: case 39: case 40: case 60: break;
            default: return authenticated_request(login, frame);
            }
            if (!peer.actor) throw CodecError("richonline_channel_selection_required");
            auto* rooms=connections->directory(connection);
            if (!rooms) throw CodecError("richonline_room_policy_not_configured");
            if (frame.wire_type == 10) {
                if (frame.payload.size() != 4) throw CodecError("richonline_character_selection_length_invalid");
                const auto character = read_le(frame.payload);
                connections->deliver(rooms->select_character(connection, character, [&] {
                    static_cast<void>(storage_.select_model(login.username_utf8, *peer.actor, character));
                }));
                return peer.drain();
            }
            const auto prior_room = rooms->room_key(connection);
            if(frame.wire_type==5) {
                if(!frame.payload.empty()) throw CodecError("richonline_room_prepare_payload_invalid");
                if(!prior_room) throw CodecError("richonline_room_peer_not_in_room");
                queue_pending_profile_refreshes(connection);
                if(!storage_.pending_game_settlement_profile_refreshes(peer.username,*peer.selected_role).empty()) {
                    if(log_) log_("richonline_game_ready_deferred",{{"connection",connection},
                        {"reason","postgame_profile_delivery_pending"}});
                    return peer.drain();
                }
            }
            auto messages = rooms->receive(connection, *peer.actor, frame);
            if (game_registry_) {
                if ((frame.wire_type == 6 || frame.wire_type == 60) && prior_room) game_registry_->cancel_room(*peer.channel,*prior_room);
                if (frame.wire_type == 5) {
                    auto snapshot = rooms->ready_game(connection);
                    if (snapshot) {
                        snapshot->channel=*peer.channel;
                        try {
                            auto redirects = game_registry_->prepare(*snapshot);
                            rooms->set_game_pending(connection, true);
                            messages.insert(messages.end(), std::make_move_iterator(redirects.begin()), std::make_move_iterator(redirects.end()));
                        } catch (const CodecError& error) {
                            // A failed game plan has not admitted this room. Keep its
                            // lobby alive and deliver the normal ready cancellation.
                            game_registry_->cancel_room(*peer.channel,snapshot->key);
                            auto cancelled=rooms->receive(connection,*peer.actor,{60,{}});
                            messages.insert(messages.end(),std::make_move_iterator(cancelled.begin()),
                                std::make_move_iterator(cancelled.end()));
                            if (log_) log_("richonline_game_start_rejected",{{"channel",*peer.channel},
                                {"room",snapshot->key},{"reason",error.what()},{"lobby_preserved",true}});
                        }
                    }
                }
            }
            connections->deliver(std::move(messages));
            return peer.drain();
        } catch (const CodecError& error) {
            if (log_) log_("richonline_request_rejected", {{"wire_type", frame.wire_type}, {"payload_bytes", frame.payload.size()}, {"reason", error.what()}});
            // All three NEW senders register a failure callback on their own
            // request ID. -1 is the explicit generic refusal policy, not a
            // claimed reconstruction of the original server's status enum.
            if(frame.wire_type==8||frame.wire_type==9||frame.wire_type==27||frame.wire_type==39)
                return std::vector<Frame>{richonline_lobby_failure(frame.wire_type,-1)};
            // A duplicate/late ballot has no effect. The kick-vote client uses
            // a different failure callback ID, so do not invent an ACK here.
            if(frame.wire_type==40) return std::vector<Frame>{};
            throw;
        }
    };
    result.drain_outbound = [connections, connection, registry = game_registry_] {
        const std::lock_guard guard(connections->mutex);
        auto* rooms=connections->directory(connection);
        if(rooms) connections->deliver(rooms->poll_votes());
        if (registry && rooms) {
            const auto room = rooms->room_key(connection);
            if(room) {
                const auto channel=*connections->peers.at(connection).channel;
                if(registry->completed_room(channel,*room)||!registry->has_room(channel,*room))
                    connections->deliver(rooms->game_finished(*room));
            }
        }
        const auto peer = connections->peers.find(connection);
        return peer == connections->peers.end() ? std::vector<Frame>{} : peer->second.drain();
    };
    result.disconnected = [connections, connection, registry = game_registry_] {
        const std::lock_guard guard(connections->mutex);
        std::exception_ptr failure;
        try {if(connections->social) connections->deliver(connections->social->leave(connection));}
        catch(...) {failure=std::current_exception();}
        auto* rooms=connections->directory(connection);
        if (rooms) {
            const auto room = rooms->room_key(connection);
            try { if (registry && room) registry->cancel_room(*connections->peers.at(connection).channel,*room); }
            catch (...) { failure = std::current_exception(); }
            connections->deliver(rooms->disconnect(connection));
        }
        connections->peers.erase(connection);
        if (failure) std::rethrow_exception(failure);
    };
    result.sent=[this,connections,connection,registry=game_registry_](const Frame& frame) {
        if(registry&&frame.wire_type==58&&registry->notify_lobby_sent(connection,frame)) {
            const std::lock_guard guard(connections->mutex);
            if(connections->peers.contains(connection)) queue_pending_profile_refreshes(connection);
        }
        if(frame.wire_type!=19) return;
        const std::lock_guard guard(connections->mutex);
        const auto found=connections->peers.find(connection);
        if(found==connections->peers.end()||!found->second.profile_attempt) return;
        auto& peer=found->second;
        const auto& attempt=*peer.profile_attempt;
        if(frame.payload.size()!=attempt.profile.size()||
            !std::equal(frame.payload.begin(),frame.payload.end(),attempt.profile.begin())) return;
        const auto confirmed=storage_.confirm_game_settlement_profile_refresh(peer.username,*peer.selected_role,
            attempt,static_cast<std::uint16_t>(frame.wire_type),frame.payload);
        if(!confirmed) throw CodecError("richonline_postgame_profile_sent_checkpoint_rejected");
        if(log_) log_("richonline_postgame_profile_sent",{{"connection",connection},
            {"operation_id",attempt.intent.operation_id},{"attempt",attempt.attempt}});
        peer.profile_attempt.reset();
        queue_pending_profile_refreshes(connection);
    };
    return make_lua_lobby_callbacks(std::move(result), storage_, log_);
}
}

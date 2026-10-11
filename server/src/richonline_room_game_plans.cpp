#include "richonline_room_game_plans.hpp"

#include <algorithm>
#include <limits>
#include <set>
#include <utility>

namespace richnet {
namespace {
void discard(RichonlineStartupPlan& plan) noexcept {
    auto disconnected=std::exchange(plan.disconnected,{});
    if(disconnected) { try { disconnected(); } catch(...) {} }
}
struct UnboundPlans {
    std::vector<RichonlineStartupPlan>& plans;
    ~UnboundPlans() { for(auto& plan:plans) discard(plan); }
};
// 若创建连接回调期间失败，尚未交给Startup的业务计划也必须释放。
struct OneShot {
    std::optional<RichonlineStartupPlan> plan;
    explicit OneShot(RichonlineStartupPlan&& value):plan(std::move(value)) {}
    ~OneShot() { if(plan) discard(*plan); }
};
}
std::vector<RichonlineGamePlan> bind_richonline_room_game_plans(const RichonlineRoomSnapshot& room,
    std::span<const RichonlineRoomBoardRecipient> expected,std::vector<RichonlineStartupPlan> plans,
    RichonlineBoardEnvelope envelope,const RichonlineRedirectFactory& redirects,
    const RichonlineFrameFiller& filler,const GameLogSink& log) {
    UnboundPlans cleanup{plans};
    if(expected.empty() || expected.size()>4 || plans.size()!=expected.size() ||
        room.participants.size()!=expected.size() || !redirects || !filler)
        throw CodecError("richonline_room_game_plans_configuration_invalid");
    auto members=room.participants;
    std::sort(members.begin(),members.end(),[](const auto& a,const auto& b){return a.slot<b.slot;});
    std::set<std::uint64_t> connections,recipients;
    std::set<std::uint32_t> actors,slots;
    for(const auto& member:members) {
        if(!member.ready || !member.connection || !member.actor || member.slot>3 ||
            member.actor>static_cast<std::uint32_t>(std::numeric_limits<std::int16_t>::max()) ||
            !connections.insert(member.connection).second || !actors.insert(member.actor).second ||
            !slots.insert(member.slot).second)
            throw CodecError("richonline_room_game_plans_membership_invalid");
    }
    if(!actors.contains(room.owner)) throw CodecError("richonline_room_game_plans_owner_missing");
    auto reference=expected.front().init;reference.local_slot=0;
    const auto canonical=encode_richonline_board_init(reference);
    const auto snapshot=encode_richonline_board_snapshot(expected.front().snapshot);
    // 先检查全体成员，之后才消耗令牌随机源或创建任何连接回调。
    for(std::size_t index=0;index<plans.size();++index) {
        const auto& peer=expected[index];const auto& plan=plans[index];
        const auto local=peer.init.local_slot;
        if(local>=members.size() || peer.connection!=members[local].connection ||
            !recipients.insert(peer.connection).second || peer.init.participants.size()!=reference.participants.size() ||
            peer.init.participants.size()<members.size() ||
            peer.snapshot.game_server_id!=peer.init.game_server_id ||
            peer.snapshot.slots.size()!=peer.init.participants.size())
            throw CodecError("richonline_room_game_plans_board_mismatch");
        for(std::size_t slot=0;slot<peer.init.participants.size();++slot) {
            const auto identity=peer.init.participants[slot].lobby_identity;
            if(slot<members.size() ? identity!=static_cast<std::int16_t>(members[slot].actor) : identity!=-1)
                throw CodecError("richonline_room_game_plans_identity_mismatch");
        }
        auto normalized=peer.init;normalized.local_slot=0;
        if(encode_richonline_board_init(normalized)!=canonical ||
            encode_richonline_board_snapshot(peer.snapshot)!=snapshot ||
            encode_richonline_board_init(plan.init)!=encode_richonline_board_init(peer.init) ||
            encode_richonline_board_snapshot(plan.snapshot)!=snapshot ||
            plan.envelope.tag!=envelope.tag || plan.envelope.mode!=envelope.mode)
            throw CodecError("richonline_room_game_plans_strategy_changed_board");
        if(!plan.map_ready || !plan.action || !plan.disconnected ||
            (plans.size()>1 && (!plan.sent || !plan.poll || !plan.map_loading)))
            throw CodecError("richonline_room_game_plans_strategy_incomplete");
    }
    std::vector<RichonlineGameRedirect> descriptors;
    descriptors.reserve(plans.size());
    for(std::size_t i=0;i<plans.size();++i) {
        auto redirect=redirects();
        static_cast<void>(encode_richonline_game_redirect(redirect));
        if(!descriptors.empty() && (redirect.address!=descriptors.front().address || redirect.port!=descriptors.front().port))
            throw CodecError("richonline_room_game_plans_endpoint_mismatch");
        if(std::any_of(descriptors.begin(),descriptors.end(),[&](const auto& previous) {
            return previous.extra==redirect.extra && previous.token==redirect.token;
        })) throw CodecError("richonline_room_game_plans_duplicate_token");
        descriptors.push_back(redirect);
    }
    std::vector<RichonlineGamePlan> result;
    result.reserve(plans.size());
    for(std::size_t index=0;index<plans.size();++index) {
        auto& plan=plans[index];
        const auto actor=members[expected[index].init.local_slot].actor;
        const auto admission=richonline_expected_admission({room.channel,room.key,actor},descriptors[index]);
        const auto sent_enabled=static_cast<bool>(plan.sent);
        auto game_finished=plan.game_finished;
        auto lobby_sent=plan.lobby_sent;
        auto terminal_pending=plan.terminal_pending;
        auto supplied=std::make_shared<OneShot>(std::move(plan));
        plan.disconnected={}; // 清理所有权已交给OneShot，防止失败路径重复通知。
        auto callbacks=make_richonline_game_callbacks([supplied](const GameAdmission&) {
            return std::exchange(supplied->plan,{});
        },filler,log);
        if(!callbacks.authorize_admission(admission))
            throw CodecError("richonline_room_game_plans_authorization_failed");
        result.push_back({expected[index].connection,actor,descriptors[index],
            [callbacks,admission] { return callbacks.admitted(admission); },
            [callbacks,admission](const Envelope299& e,View plain) { return callbacks.message(admission,e,plain); },
            [callbacks,admission] { callbacks.disconnected(admission); },
            [callbacks,admission] { return callbacks.poll(admission); },
            sent_enabled ? std::function<void(const Frame&)>{[callbacks,admission](const Frame& frame) {
                callbacks.sent(admission,frame);
            }} : std::function<void(const Frame&)>{},std::move(game_finished),std::move(lobby_sent),std::move(terminal_pending)});
    }
    return result;
}
}

#include "richonline_shared_startup.hpp"
#include "richonline_game_end.hpp"

#include <algorithm>
#include <deque>
#include <mutex>

namespace richnet {
namespace {
constexpr std::size_t queue_limit=256,request_limit=64,byte_limit=1024U*1024U;
struct Peer {
    Bytes init,snapshot;
    bool connected=true,loaded=false,init_sent=false,snapshot_sent=false;
    std::deque<Bytes> pending,in_flight;
};
struct Request {
    std::uint8_t actor;
    Envelope299 envelope;
    Bytes plain;
    std::optional<RichonlineStockRequest> stock;
};
struct IncomingCallbacks {
    RichonlineSharedCallbacks& callbacks;
    std::array<bool,8> actors{};
    bool owned=true;
    ~IncomingCallbacks() {
        if(!owned || !callbacks.disconnected) return;
        for(std::uint8_t actor=0;actor<actors.size();++actor) if(actors[actor])
            try { callbacks.disconnected(actor); } catch(...) {}
    }
};
struct Shared {
    std::mutex mutex;
    std::uint16_t game;
    RichonlineSharedCallbacks callbacks;
    std::vector<std::optional<Peer>> peers;
    std::deque<Request> requests;
    bool started=false,failed=false;
    std::function<RichonlineMapLoadPolicy::Clock::time_point()> now;
    struct Movement {
        RichonlineSharedMovementWait entry;
        std::optional<RichonlineMapLoadPolicy::Clock::time_point> deadline;
        std::array<bool,8> reported{};
        std::optional<Request> controller;
    };
    std::optional<Movement> movement;
    std::optional<std::uint64_t> last_movement_sequence;
    std::deque<RichonlineSharedMovementWait> retired_movements;
    ~Shared() {
        // 计划已创建但尚未交给注册表时也拥有清理责任；显式断开的槽不重复通知。
        if(!callbacks.disconnected) return;
        for(std::uint8_t actor=0;actor<peers.size();++actor) if(peers[actor] && peers[actor]->connected) {
            peers[actor]->connected=false;
            try { callbacks.disconnected(actor); } catch(...) {}
        }
    }

    static bool matches_movement(const RichonlineSharedMovementWait& entry,View plain) {
        return plain.size()==6 && read_le(plain.first(2))==entry.opcode &&
            read_le(plain.subspan(2,2))==entry.calendar &&
            read_le(plain.subspan(4,2))==static_cast<std::uint16_t>(entry.endpoint);
    }
    bool retired_movement(std::uint8_t actor,View plain) const {
        if(actor>=peers.size() || !peers[actor]) return false;
        return std::any_of(retired_movements.begin(),retired_movements.end(),[&](const auto& entry) {
            return matches_movement(entry,plain);
        });
    }
    void retire_movement() {
        retired_movements.push_back(movement->entry);
        if(retired_movements.size()>64) retired_movements.pop_front();
        movement.reset();
    }
    void sync_movement() {
        if(!callbacks.movement_wait) return;
        const auto current=callbacks.movement_wait();
        if(current && ((current->opcode!=0x11 && current->opcode!=0x28) ||
            current->endpoint<0 || current->controller>=peers.size() ||
            !peers[current->controller] || !peers[current->controller]->connected))
            throw CodecError("richonline_shared_movement_wait_invalid");
        if(movement && current && *current==movement->entry) return;
        // 业务撤销移动时仅保留迟到回报指纹，不能据此调用落点或补齐未收到的回报。
        if(movement) retire_movement();
        if(!current) return;
        if(last_movement_sequence && current->sequence<=*last_movement_sequence)
            throw CodecError("richonline_shared_movement_sequence_not_advanced");
        movement=Movement{*current,{},{},{}};
        last_movement_sequence=current->sequence;
    }
    std::optional<Request> accept_movement(Request request) {
        if(!callbacks.movement_wait || request.stock || request.plain.size()<2 ||
            (read_le(View(request.plain).first(2))!=0x11 && read_le(View(request.plain).first(2))!=0x28)) return request;
        if(!movement || !matches_movement(movement->entry,request.plain)) {
            if(retired_movement(request.actor,request.plain)) return {};
            if(movement) throw CodecError("richonline_shared_movement_report_mismatch");
            return request; // 未声明此等待时仍交给业务明确处理，不吞未知上报。
        }
        const auto sender=request.actor;
        if(movement->reported[sender]) return {};
        if(sender==movement->entry.controller) movement->controller=std::move(request);
        movement->reported[sender]=true;
        for(std::size_t actor=0;actor<peers.size();++actor)
            if(peers[actor] && peers[actor]->connected && !movement->reported[actor]) return {};
        if(!movement->controller) throw CodecError("richonline_shared_movement_controller_missing");
        auto confirmed=std::move(movement->controller);
        retire_movement();
        return confirmed;
    }

    Peer& peer(std::uint8_t actor) {
        if(actor>=peers.size() || !peers[actor] || !peers[actor]->connected)
            throw CodecError("richonline_shared_peer_unavailable");
        return *peers[actor];
    }
    void healthy() const {
        if(failed) throw CodecError("richonline_shared_session_failed");
    }
    bool ready() const {
        return std::all_of(peers.begin(),peers.end(),[](const auto& p) {
            return !p || (p->connected && p->loaded && p->init_sent && p->snapshot_sent);
        });
    }
    bool drained() const {
        return std::all_of(peers.begin(),peers.end(),[](const auto& p) {
            return !p || !p->connected || (p->pending.empty() && p->in_flight.empty());
        });
    }
    void publish(RichonlineSharedMessages messages) {
        // 全部目的地、局号与容量先校验，复制成功才替换各连接队列。
        // 业务异常或分配失败会使整局失效；不自动重跑已调用的业务事务。
        std::vector<std::deque<Bytes>> next(peers.size());
        for(std::size_t i=0;i<peers.size();++i) if(peers[i]) next[i]=peers[i]->pending;
        for(const auto& message:messages) {
            const View plain(message.plain);
            if(plain.size()<4 || plain.size()>509 || read_le(plain.subspan(2,2))!=game ||
                read_le(plain.first(2))==0x4000 ||
                read_le(plain.first(2))==0x4006)
                throw CodecError("richonline_shared_response_invalid");
            const auto opcode=read_le(plain.first(2));
            if((opcode==0x4010 || opcode==0x4004) && message.recipient)
                throw CodecError("richonline_shared_turn_must_broadcast");
            if(opcode==0x4004 && plain.size()!=12+12*peers.size())
                throw CodecError("richonline_shared_snapshot_size_invalid");
            if(opcode==0x4010 && (plain.size()<7 || plain[4]>=peers.size()))
                throw CodecError("richonline_shared_turn_invalid");
            if(message.recipient && (*message.recipient>=peers.size() || !peers[*message.recipient]))
                throw CodecError("richonline_shared_recipient_invalid");
            for(std::size_t i=0;i<peers.size();++i)
                if(peers[i] && peers[i]->connected && (!message.recipient || *message.recipient==i)) {
                    if(next[i].size()+peers[i]->in_flight.size()>=queue_limit)
                        throw CodecError("richonline_shared_outbox_full");
                    next[i].push_back(message.plain);
                }
        }
        std::size_t bytes=0;
        for(std::size_t i=0;i<peers.size();++i) if(peers[i]) {
            if(next[i].size()+peers[i]->in_flight.size()>queue_limit)
                throw CodecError("richonline_shared_outbox_full");
            for(const auto& plain:next[i]) bytes+=plain.size();
            for(const auto& plain:peers[i]->in_flight) bytes+=plain.size();
        }
        if(bytes>byte_limit) throw CodecError("richonline_shared_outbox_full");
        for(std::size_t i=0;i<peers.size();++i) if(peers[i]) peers[i]->pending.swap(next[i]);
    }
    void drive(bool timer) {
        healthy();
        if(!ready() && !started) return;
        if(!started) { publish(callbacks.opening());started=true; }
        sync_movement();
        if(movement && movement->deadline && now()>=*movement->deadline)
            throw CodecError("richonline_shared_movement_report_timeout");
        if(!drained()) return;
        // 全员完整发包确认后才开始计上报时限；网络发送中的时间不算客户端动画超时。
        if(movement && !movement->deadline) movement->deadline=now()+callbacks.movement_timeout;
        // 收包按到达顺序处理；有输出即等待整批发送，不丢弃期间收到的合法操作。
        while(!requests.empty() && drained()) {
            auto request=std::move(requests.front());requests.pop_front();
            if(!peers[request.actor]->connected) continue;
            auto accepted=accept_movement(std::move(request));
            if(!accepted) continue;
            publish(accepted->stock ? callbacks.stock_action(accepted->actor,*accepted->stock) :
                callbacks.action(accepted->actor,accepted->envelope,accepted->plain));
            sync_movement();
        }
        if(timer && drained() && callbacks.poll) {
            publish(callbacks.poll());
            sync_movement();
        }
    }
    std::vector<Bytes> take(std::uint8_t actor) {
        auto& p=peer(actor);
        std::vector<Bytes> result(p.pending.begin(),p.pending.end());
        auto flight=p.in_flight;
        flight.insert(flight.end(),p.pending.begin(),p.pending.end());
        p.in_flight.swap(flight);p.pending.clear();
        return result;
    }
    std::vector<Bytes> enqueue(Request request) {
        healthy();
        if(!peer(request.actor).loaded) throw CodecError("richonline_shared_action_before_ready");
        if(requests.size()>=request_limit || request.plain.size()>510)
            throw CodecError("richonline_shared_inbox_full");
        const auto actor=request.actor;
        requests.push_back(std::move(request));drive(false);
        return take(actor);
    }
    template<class Function> auto guarded(Function&& function) {
        const std::lock_guard lock(mutex);
        try { healthy();return function(); }
        catch(...) { failed=true;throw; }
    }
    void delivered(std::uint8_t actor,View plain) {
        auto& p=peer(actor);
        const auto equal=[&](const Bytes& expected) {
            return std::equal(plain.begin(),plain.end(),expected.begin(),expected.end());
        };
        if(!p.init_sent && equal(p.init)) p.init_sent=true;
        else if(p.loaded && p.init_sent && !p.snapshot_sent && equal(p.snapshot)) p.snapshot_sent=true;
        else if(equal(richonline_leave_ack(game))) return; // 000A由外层连接独立处理。
        else {
            if(p.in_flight.empty() || !equal(p.in_flight.front()))
                throw CodecError("richonline_shared_sent_out_of_order");
            p.in_flight.pop_front();
        }
        if(callbacks.sent) callbacks.sent(actor,plain);
    }
    void disconnect(std::uint8_t actor) {
        const std::lock_guard lock(mutex);
        auto& p=*peers.at(actor);
        if(!p.connected) return;
        p.connected=false;p.pending.clear();p.in_flight.clear();
        std::erase_if(requests,[&](const auto& request){return request.actor==actor;});
        // 不能因一个必需客户端离线而把“全员一致”缩成剩余玩家一致。
        if(!started || callbacks.movement_wait) failed=true;
        try { callbacks.disconnected(actor); }
        catch(...) { failed=true;throw; }
    }
};
}
std::vector<RichonlineStartupPlan> make_richonline_shared_startups(
    std::vector<RichonlineBoardInit> inits,RichonlineBoardSnapshot snapshot,
    RichonlineBoardEnvelope envelope,RichonlineSharedCallbacks callbacks,RichonlineMapLoadPolicy loading) {
    IncomingCallbacks cleanup{callbacks};
    for(const auto& init:inits) if(init.local_slot<cleanup.actors.size()) cleanup.actors[init.local_slot]=true;
    if(inits.empty() || inits.size()>4 || !callbacks.opening || !callbacks.action || !callbacks.disconnected ||
        !loading.now || loading.timeout<std::chrono::seconds{1} || loading.timeout>std::chrono::minutes{10} ||
        (callbacks.movement_wait && (callbacks.movement_timeout<std::chrono::seconds{1} ||
            callbacks.movement_timeout>std::chrono::minutes{5})))
        throw CodecError("richonline_shared_configuration_invalid");
    const auto initial_snapshot=encode_richonline_board_snapshot(snapshot);
    const auto reference=encode_richonline_board_init(inits.front());
    auto state=std::make_shared<Shared>();state->game=snapshot.game_server_id;
    state->now=loading.now;
    state->peers.resize(inits.front().participants.size());
    for(const auto& init:inits) {
        if(init.game_server_id!=snapshot.game_server_id || init.participants.size()!=snapshot.slots.size())
            throw CodecError("richonline_shared_board_mismatch");
        const auto encoded=encode_richonline_board_init(init);
        auto canonical=init;canonical.local_slot=inits.front().local_slot;
        if(encode_richonline_board_init(canonical)!=reference || state->peers[init.local_slot])
            throw CodecError("richonline_shared_board_mismatch");
        Peer peer;peer.init=encoded;peer.snapshot=initial_snapshot;
        state->peers[init.local_slot]=std::move(peer);
    }
    for(std::size_t i=0;i<state->peers.size();++i)
        if((inits.front().participants[i].lobby_identity>=0)!=state->peers[i].has_value())
            throw CodecError("richonline_shared_membership_mismatch");
    state->callbacks=std::move(callbacks);
    cleanup.owned=false;
    std::vector<RichonlineStartupPlan> result;
    for(auto& init:inits) {
        const auto actor=init.local_slot;
        RichonlineStartupPlan plan;
        plan.init=std::move(init);plan.snapshot=snapshot;plan.envelope=envelope;plan.map_loading=loading;
        plan.map_ready=[state,actor] { return state->guarded([&] {
            state->peer(actor).loaded=true;return std::vector<Bytes>{};
        }); };
        plan.action=[state,actor](const Envelope299& e,View plain) { return state->guarded([&] {
            return state->enqueue({actor,e,Bytes(plain.begin(),plain.end()),{}});
        }); };
        plan.disconnected=[state,actor] { state->disconnect(actor); };
        plan.poll=[state,actor] { return state->guarded([&] {state->drive(true);return state->take(actor);}); };
        plan.sent=[state,actor](View plain) { state->guarded([&] {state->delivered(actor,plain);}); };
        if(state->callbacks.stock_action) plan.stock_action=[state,actor](const RichonlineStockRequest& request) {
            return state->guarded([&] {return state->enqueue({actor,{}, {},request});});
        };
        if(state->callbacks.retired_action || state->callbacks.movement_wait) plan.retired_action=[state,actor](View plain) {
            return state->guarded([&] {
                return state->retired_movement(actor,plain) ||
                    (state->callbacks.retired_action && state->callbacks.retired_action(actor,plain));
            });
        };
        if(state->callbacks.game_finished) plan.game_finished=[state,actor] {
            const std::lock_guard lock(state->mutex);
            const auto& p=*state->peers[actor];
            return p.snapshot_sent && p.pending.empty() && p.in_flight.empty() && state->callbacks.game_finished(actor);
        };
        if(state->callbacks.lobby_sent) plan.lobby_sent=[state,actor](const Frame& frame) {
            const std::lock_guard lock(state->mutex);
            state->callbacks.lobby_sent(actor,frame);
        };
        if(state->callbacks.terminal_pending) plan.terminal_pending=[state,actor] {
            // 游戏通道故障也必须保留已持久化的结算状态，不能被healthy门遮住。
            const std::lock_guard lock(state->mutex);
            return state->callbacks.terminal_pending(actor);
        };
        result.push_back(std::move(plan));
    }
    return result;
}
}

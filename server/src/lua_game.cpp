#include "lua_game.hpp"
#include "lua_wire.hpp"
#include <utility>

namespace richnet {
GameCallbacks make_lua_game_callbacks(GameCallbacks native) {
    auto runtime = LuaServer::create();
    if (!runtime) return native;
    auto shared = std::make_shared<GameCallbacks>(std::move(native));
    auto result = *shared;
    result.admitted = [runtime, shared](const GameAdmission& admission) {
        auto frames = shared->admitted ? shared->admitted(admission) : std::vector<Frame>{};
        auto extra = lua_frames(runtime->call("network.admitted", LuaValue::object()));
        frames.insert(frames.end(), extra.begin(), extra.end()); return frames;
    };
    result.message = [runtime, shared](const GameAdmission& admission, const Envelope299& envelope, View plain) {
        bool called = false;
        const LuaBindings api{{"network.native", [&](const LuaValue&) {
            if (std::exchange(called, true)) throw CodecError("lua_native_request_already_called");
            if (!shared->message) throw CodecError("game_message_handler_not_configured");
            return lua_frames(shared->message(admission, envelope, plain));
        }}};
        return lua_frames(runtime->call("network.game", {{"payload", lua_bytes(plain)},
            {"opcode", plain.size() >= 2 ? read_le(plain.first(2)) : 0}}, api));
    };
    result.poll = [runtime, shared](const GameAdmission& admission) {
        auto frames = shared->poll ? shared->poll(admission) : std::vector<Frame>{};
        auto extra = lua_frames(runtime->call("network.poll", LuaValue::object()));
        frames.insert(frames.end(), extra.begin(), extra.end()); return frames;
    };
    result.disconnected = [runtime, shared](const GameAdmission& admission) {
        if (shared->disconnected) shared->disconnected(admission);
        runtime->call("network.disconnected", LuaValue::object());
    };
    // 保留原生 sent_enabled 门：结算的“整帧发送完成”确认不能提前或伪造。
    result.sent = [runtime, shared](const GameAdmission& admission, const Frame& frame) {
        if (shared->sent) shared->sent(admission, frame);
        runtime->call("network.sent", lua_frame(frame));
    };
    return result;
}
}

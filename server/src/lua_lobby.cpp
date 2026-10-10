#include "lua_lobby.hpp"
#include "lua_wire.hpp"
#include <utility>

namespace richnet {
LobbyCallbacks make_lua_lobby_callbacks(LobbyCallbacks native, Storage& storage, ControlLog log) {
    auto runtime = LuaServer::create();
    if (!runtime) return native;
    auto shared = std::make_shared<LobbyCallbacks>(std::move(native));
    auto bindings = [&storage, log](const std::string& username) {
        return LuaBindings{
            {"db.batch", [&storage](const LuaValue& args) { return storage.script_batch(args); }},
            {"db.roles", [&storage, username](const LuaValue&) { return storage.roles_for_username(username); }},
            {"log", [log](const LuaValue& args) { if (log) log("lua_lobby", args); return LuaValue{}; }}
        };
    };
    LobbyCallbacks result = *shared;
    result.login_responses = [runtime, shared, bindings](const LobbyLogin& login) {
        auto api = bindings(login.username_utf8); bool called = false;
        api.emplace("lobby.native", [&](const LuaValue&) {
            if (std::exchange(called, true)) throw CodecError("lua_native_request_already_called");
            return lua_frames(shared->login_responses(login));
        });
        return lua_frames(runtime->call("lobby.login", {{"username", login.username_utf8}}, api));
    };
    result.authenticated_request = [runtime, shared, bindings](const LobbyLogin& login, const Frame& frame) {
        auto api = bindings(login.username_utf8); bool called = false;
        api.emplace("lobby.native", [&](const LuaValue&) {
            if (std::exchange(called, true)) throw CodecError("lua_native_request_already_called");
            return lua_frames(shared->authenticated_request(login, frame));
        });
        auto request = lua_frame(frame); request["username"] = login.username_utf8;
        return lua_frames(runtime->call("lobby.request", request, api));
    };
    result.drain_outbound = [runtime, shared] {
        auto frames = shared->drain_outbound ? shared->drain_outbound() : std::vector<Frame>{};
        auto extra = lua_frames(runtime->call("lobby.poll", LuaValue::object()));
        frames.insert(frames.end(), extra.begin(), extra.end()); return frames;
    };
    result.disconnected = [runtime, shared] {
        if (shared->disconnected) shared->disconnected();
        runtime->call("lobby.disconnected", LuaValue::object());
    };
    result.sent = [runtime, shared](const Frame& frame) {
        if (shared->sent) shared->sent(frame);
        runtime->call("lobby.sent", lua_frame(frame));
    };
    return result;
}
}

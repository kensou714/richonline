#pragma once
#include "lobby.hpp"
#include "storage.hpp"
#include "control.hpp"
namespace richnet {
LobbyCallbacks make_lua_lobby_callbacks(LobbyCallbacks native, Storage& storage, ControlLog log);
}

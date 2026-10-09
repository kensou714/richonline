#include "codec.hpp"
#include "lua_policy.hpp"

extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
}

#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>

namespace richnet {
namespace {
struct RandomDraws {
    std::span<const std::int64_t> values;
    std::size_t cursor = 0;
};

int injected_rng(lua_State* state) {
    auto* draws = static_cast<RandomDraws*>(lua_touserdata(state, lua_upvalueindex(1)));
    const auto upper = luaL_checkinteger(state, 1);
    if (upper <= 0) return luaL_error(state, "invalid_random_upper");
    if (draws->cursor >= draws->values.size()) return luaL_error(state, "random_draws_exhausted");
    const auto value = draws->values[draws->cursor++];
    if (value < 0 || value >= upper) return luaL_error(state, "random_draw_out_of_range");
    lua_pushinteger(state, value);
    return 1;
}

void checked_call(lua_State* state, int arguments, int results) {
    if (lua_pcall(state, arguments, results, 0) != LUA_OK) {
        const auto* detail = lua_tostring(state, -1);
        if (detail == nullptr) throw CodecError("lua_error_non_string");
        throw CodecError(std::string("lua_error:") + detail);
    }
}
}

std::vector<std::string> run_policy(const std::string& path, std::span<const std::int64_t> draws) {
    const std::unique_ptr<lua_State, decltype(&lua_close)> state(luaL_newstate(), &lua_close);
    if (!state) throw CodecError("lua_state_allocation_failed");
    luaL_openlibs(state.get());
    std::ifstream file(std::filesystem::path(std::u8string(path.begin(), path.end())), std::ios::binary);
    if (!file) throw CodecError("lua_file_open_failed");
    const std::string source((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (luaL_loadbufferx(state.get(), source.data(), source.size(), path.c_str(), "t") != LUA_OK)
        throw CodecError(std::string("lua_error:") + lua_tostring(state.get(), -1));
    checked_call(state.get(), 0, 1);
    if (!lua_istable(state.get(), -1)) throw CodecError("lua_module_must_be_table");
    lua_getfield(state.get(), -1, "select_attacks");
    if (!lua_isfunction(state.get(), -1)) throw CodecError("lua_policy_function_missing");
    lua_getfield(state.get(), -2, "config");
    if (!lua_istable(state.get(), -1)) throw CodecError("lua_config_must_be_table");
    RandomDraws random{draws};
    lua_pushlightuserdata(state.get(), &random);
    lua_pushcclosure(state.get(), injected_rng, 1);
    checked_call(state.get(), 2, 1);
    if (!lua_istable(state.get(), -1)) throw CodecError("lua_policy_result_must_be_table");
    const auto count = lua_rawlen(state.get(), -1);
    if (count > 8) throw CodecError("lua_policy_result_exceeds_attempt_limit");
    std::vector<std::string> attacks;
    for (std::size_t index = 1; index <= count; ++index) {
        lua_rawgeti(state.get(), -1, static_cast<lua_Integer>(index));
        if (lua_type(state.get(), -1) != LUA_TSTRING) throw CodecError("lua_policy_result_must_be_string");
        std::size_t length = 0;
        const auto* value = lua_tolstring(state.get(), -1, &length);
        const std::string attack(value, length);
        if (attack != "idle" && attack != "mine" && attack != "weapon:1046" &&
            attack != "weapon:1063" && attack != "weapon:1075")
            throw CodecError("lua_policy_unknown_attack");
        attacks.push_back(attack);
        lua_pop(state.get(), 1);
    }
    if (random.cursor != draws.size()) throw CodecError("random_draws_remaining");
    return attacks;
}
}

#include "lua_server.hpp"
extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
}
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <mutex>
#include <set>
#include <stdexcept>

namespace richnet {
namespace {
struct Scripts {
    std::filesystem::path root;
    std::map<std::string, std::string> sources;
    std::uint64_t generation = 0;
};
std::mutex configuration_mutex;
std::shared_ptr<const Scripts> configured;
char null_value;
constexpr std::size_t memory_limit = 64U * 1024U * 1024U;
constexpr int instruction_limit = 2000000;
void push_value(lua_State* state, const LuaValue& value, unsigned depth = 0) {
    if (depth > 40) throw std::runtime_error("lua_value_depth_exceeded");
    if (!lua_checkstack(state,4)) throw std::runtime_error("lua_stack_allocation_failed");
    if (value.is_null()) lua_pushlightuserdata(state, &null_value);
    else if (value.is_boolean()) lua_pushboolean(state, value.get<bool>());
    else if (value.is_number_unsigned()) {
        const auto number = value.get<std::uint64_t>();
        if (number > static_cast<std::uint64_t>(std::numeric_limits<lua_Integer>::max()))
            throw std::runtime_error("lua_integer_overflow");
        lua_pushinteger(state, static_cast<lua_Integer>(number));
    } else if (value.is_number_integer()) lua_pushinteger(state, value.get<lua_Integer>());
    else if (value.is_number_float()) lua_pushnumber(state, value.get<lua_Number>());
    else if (value.is_string()) {
        const auto& text = value.get_ref<const std::string&>();
        lua_pushlstring(state, text.data(), text.size());
    } else if (value.is_array()) {
        lua_createtable(state, static_cast<int>(value.size()), 0);
        luaL_setmetatable(state, "richonline.array");
        lua_Integer index = 0;
        for (const auto& entry : value) { push_value(state, entry, depth + 1); lua_rawseti(state, -2, ++index); }
    } else if (value.is_object()) {
        lua_createtable(state, 0, static_cast<int>(value.size()));
        for (const auto& [key, entry] : value.items()) {
            lua_pushlstring(state, key.data(), key.size()); push_value(state, entry, depth + 1); lua_rawset(state, -3);
        }
    } else throw std::runtime_error("lua_value_type_unsupported");
}
LuaValue read_value(lua_State* state, int index, unsigned depth = 0) {
    if (depth > 40) throw std::runtime_error("lua_value_cycle_or_depth_exceeded");
    if (!lua_checkstack(state,4)) throw std::runtime_error("lua_stack_allocation_failed");
    index = lua_absindex(state, index);
    switch (lua_type(state, index)) {
    case LUA_TNIL: return nullptr;
    case LUA_TLIGHTUSERDATA:
        if (lua_touserdata(state, index) == &null_value) return nullptr;
        break;
    case LUA_TBOOLEAN: return lua_toboolean(state, index) != 0;
    case LUA_TNUMBER:
        if (lua_isinteger(state, index)) return lua_tointeger(state, index);
        if (!std::isfinite(lua_tonumber(state, index))) throw std::runtime_error("lua_number_not_finite");
        return lua_tonumber(state, index);
    case LUA_TSTRING: {
        std::size_t size = 0; const auto* text = lua_tolstring(state, index, &size);
        return std::string(text, size);
    }
    case LUA_TTABLE: {
        const auto count = lua_rawlen(state, index);
        bool array = count != 0;
        if (lua_getmetatable(state, index)) {
            luaL_getmetatable(state, "richonline.array"); array = array || lua_rawequal(state, -1, -2);
            lua_pop(state, 2);
        }
        LuaValue result = array ? LuaValue::array() : LuaValue::object();
        std::size_t keys = 0;
        lua_pushnil(state);
        while (lua_next(state, index)) {
            if (++keys > 65536) throw std::runtime_error("lua_table_limit_exceeded");
            if (array) {
                if (!lua_isinteger(state, -2) || lua_tointeger(state, -2) < 1 ||
                    static_cast<std::uint64_t>(lua_tointeger(state, -2)) > count)
                    throw std::runtime_error("lua_array_keys_invalid");
            } else {
                if (lua_type(state, -2) != LUA_TSTRING) throw std::runtime_error("lua_object_keys_invalid");
                std::size_t size = 0; const auto* key = lua_tolstring(state, -2, &size);
                result[std::string(key, size)] = read_value(state, -1, depth + 1);
            }
            lua_pop(state, 1);
        }
        if (array) {
            if (keys != count) throw std::runtime_error("lua_array_holes_invalid");
            for (std::size_t i = 1; i <= count; ++i) {
                lua_rawgeti(state, index, static_cast<lua_Integer>(i));
                result.push_back(read_value(state, -1, depth + 1)); lua_pop(state, 1);
            }
        }
        return result;
    }
    }
    throw std::runtime_error("lua_return_type_unsupported");
}
int push_trampoline(lua_State* state) {
    try {
        const auto* value=static_cast<const LuaValue*>(lua_touserdata(state,1));
        if(!value) throw std::runtime_error("lua_push_value_missing");
        push_value(state,*value);return 1;
    } catch(const std::exception& error) {lua_pushstring(state,error.what());}
    return lua_error(state);
}
void protected_push(lua_State* state,const LuaValue& value) {
    // JSON 的生命周期留在 pcall 外；Lua 内存不足时不会跨过 C++ JSON 析构。
    if(!lua_checkstack(state,8)) throw std::runtime_error("lua_stack_allocation_failed");
    lua_pushcfunction(state,push_trampoline);
    lua_pushlightuserdata(state,const_cast<LuaValue*>(&value));
    if(lua_pcall(state,1,1,0)!=LUA_OK) {
        const auto* detail=lua_tostring(state,-1);
        throw std::runtime_error(std::string("lua_value_push_failed:")+(detail?detail:"unknown"));
    }
}
}

struct LuaServer::Impl {
    std::shared_ptr<const Scripts> scripts;
    lua_State* state = nullptr;
    const LuaBindings* bindings = nullptr;
    std::recursive_mutex mutex;
    std::size_t allocated = 0;
    int remaining = instruction_limit;
    int module = LUA_NOREF;
    std::set<std::string> loading;
    std::map<std::string, int> loaded;
    static void* allocator(void* context, void* pointer, std::size_t old_size, std::size_t size) {
        auto& self = *static_cast<Impl*>(context);
        if (!pointer) old_size = 0;
        if (size == 0) { self.allocated -= old_size; std::free(pointer); return nullptr; }
        if (size > memory_limit || self.allocated - old_size > memory_limit - size) return nullptr;
        void* next = std::realloc(pointer, size);
        if (next) self.allocated = self.allocated - old_size + size;
        return next;
    }
    static Impl& self(lua_State* state) { return **static_cast<Impl**>(lua_getextraspace(state)); }
    static void budget(lua_State* state, lua_Debug*) {
        auto& runtime = self(state); runtime.remaining -= 1000;
        if (runtime.remaining <= 0) luaL_error(state, "lua_instruction_budget_exceeded");
    }
    static int native(lua_State* state) {
        // 离开 catch/局部对象作用域后才 lua_error，避免 longjmp 跳过 C++ 析构。
        try {
            auto& runtime = self(state);
            if (!runtime.bindings) throw std::runtime_error("lua_core_outside_event");
            if (lua_type(state, 1) != LUA_TSTRING) throw std::runtime_error("lua_core_name_required");
            const std::string name = lua_tostring(state, 1);
            const auto found = runtime.bindings->find(name);
            if (found == runtime.bindings->end()) throw std::runtime_error("lua_core_unavailable:" + name);
            const auto request = lua_gettop(state) < 2 ? LuaValue::object() : read_value(state, 2);
            const auto result = found->second(request);
            protected_push(state, result); return 1;
        } catch (const std::exception& error) { lua_pushstring(state, error.what()); }
          catch (...) { lua_pushliteral(state, "lua_core_unknown_exception"); }
        return lua_error(state);
    }
    static int list(lua_State* state) {
        try {
            LuaValue result = LuaValue::array();
            if (self(state).bindings) for (const auto& [name, unused] : *self(state).bindings) {
                static_cast<void>(unused); result.push_back(name);
            }
            protected_push(state, result); return 1;
        } catch (const std::exception& error) { lua_pushstring(state, error.what()); }
        return lua_error(state);
    }
    static int array(lua_State* state) {
        if (lua_gettop(state) == 0) lua_newtable(state);
        else { luaL_checktype(state, 1, LUA_TTABLE); lua_settop(state, 1); }
        luaL_setmetatable(state, "richonline.array"); return 1;
    }
    static int require(lua_State* state) {
        try {
            if (lua_type(state, 1) != LUA_TSTRING) throw std::runtime_error("lua_module_name_required");
            self(state).load(lua_tostring(state, 1)); return 1;
        } catch (const std::exception& error) { lua_pushstring(state, error.what()); }
        return lua_error(state);
    }
    static int traceback(lua_State* state) {
        const auto* message = lua_tostring(state, 1);
        luaL_traceback(state, state, message ? message : "lua_error_non_string", 1); return 1;
    }
    void checked_call(int arguments, int results) {
        const int base = lua_gettop(state) - arguments;
        lua_pushcfunction(state, traceback); lua_insert(state, base);
        const auto result = lua_pcall(state, arguments, results, base);
        lua_remove(state, base);
        if (result != LUA_OK) {
            const auto* detail = lua_tostring(state, -1);
            throw std::runtime_error(std::string("lua_script_error:") + (detail ? detail : "unknown"));
        }
    }
    void load(const std::string& name) {
        if (name.empty() || name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.") != name.npos ||
            name.find("..") != name.npos) throw std::runtime_error("lua_module_name_invalid");
        if (const auto found = loaded.find(name); found != loaded.end()) { lua_rawgeti(state, LUA_REGISTRYINDEX, found->second); return; }
        const auto found = scripts->sources.find(name);
        if (found == scripts->sources.end()) throw std::runtime_error("lua_module_missing:" + name);
        if (!loading.insert(name).second) throw std::runtime_error("lua_module_cycle:" + name);
        try {
            const auto filename = "@scripts/" + name;
            if (luaL_loadbufferx(state, found->second.data(), found->second.size(), filename.c_str(), "t") != LUA_OK)
                throw std::runtime_error(std::string("lua_compile_error:") + lua_tostring(state, -1));
            checked_call(0, 1);
            if (!lua_istable(state, -1)) throw std::runtime_error("lua_module_table_required:" + name);
            lua_pushvalue(state, -1); loaded.emplace(name, luaL_ref(state, LUA_REGISTRYINDEX));
            loading.erase(name);
        } catch (...) { loading.erase(name); throw; }
    }
    explicit Impl(std::shared_ptr<const Scripts> source) : scripts(std::move(source)) {
        state = lua_newstate(allocator, this);
        if (!state) throw std::runtime_error("lua_state_allocation_failed");
        *static_cast<Impl**>(lua_getextraspace(state)) = this;
        try {
            // 不开放本地 DLL、系统命令或文件写入。资源/数据库统一走带上下文的核心接口。
            for (const auto& lib : {std::pair{"_G", luaopen_base}, {"table", luaopen_table},
                    {"string", luaopen_string}, {"math", luaopen_math}, {"utf8", luaopen_utf8}}) {
                luaL_requiref(state, lib.first, lib.second, 1); lua_pop(state, 1);
            }
            for (const auto* name : {"dofile", "loadfile", "load", "collectgarbage", "print"}) { lua_pushnil(state); lua_setglobal(state, name); }
            luaL_newmetatable(state, "richonline.array"); lua_pop(state, 1);
            lua_newtable(state);
            lua_pushcfunction(state, native); lua_setfield(state, -2, "call");
            lua_pushcfunction(state, list); lua_setfield(state, -2, "capabilities");
            lua_pushcfunction(state, array); lua_setfield(state, -2, "array");
            lua_pushlightuserdata(state, &null_value); lua_setfield(state, -2, "null");
            lua_pushinteger(state, 1); lua_setfield(state, -2, "api_version");
            lua_setglobal(state, "core");
            lua_pushcfunction(state, require); lua_setglobal(state, "require");
            lua_sethook(state, budget, LUA_MASKCOUNT, 1000);
            // 所有文件在发布时编译，未被 require 的模块也不能带语法错误上线。
            for (const auto& [name, text] : scripts->sources) {
                if (luaL_loadbufferx(state, text.data(), text.size(), name.c_str(), "t") != LUA_OK)
                    throw std::runtime_error(std::string("lua_compile_error:") + lua_tostring(state, -1));
                lua_pop(state, 1);
            }
            load("main");
            lua_getfield(state,-1,"dispatch");
            if(!lua_isfunction(state,-1)) throw std::runtime_error("lua_dispatch_missing");
            lua_pop(state,1);module = luaL_ref(state, LUA_REGISTRYINDEX);
        } catch (...) { lua_close(state); state = nullptr; throw; }
    }
    ~Impl() { if (state) lua_close(state); }
};

LuaServer::LuaServer(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
LuaServer::~LuaServer() = default;
void LuaServer::configure(const std::filesystem::path& root) {
    auto source = std::make_shared<Scripts>(); source->root = std::filesystem::canonical(root);
    std::size_t bytes = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(source->root)) {
        if (!entry.is_regular_file() || entry.path().extension() != ".lua") continue;
        if (entry.is_symlink()) throw std::runtime_error("lua_symlink_not_supported");
        const auto relative = entry.path().lexically_relative(source->root);
        auto module = relative.generic_string(); module.resize(module.size() - 4);
        for (auto& character : module) if (character == '/') character = '.';
        std::ifstream stream(entry.path(), std::ios::binary);
        if (!stream) throw std::runtime_error("lua_source_open_failed:" + module);
        auto text = std::string(std::istreambuf_iterator<char>(stream), {});
        bytes += text.size();
        if (bytes > 8U * 1024U * 1024U || source->sources.size() >= 2048) throw std::runtime_error("lua_source_limit_exceeded");
        if (!source->sources.emplace(module, std::move(text)).second) throw std::runtime_error("lua_module_duplicate");
    }
    const auto validation = std::make_unique<Impl>(source);
    std::lock_guard guard(configuration_mutex);
    source->generation = configured ? configured->generation + 1 : 1;
    configured = std::move(source);
}
std::shared_ptr<LuaServer> LuaServer::create() {
    std::shared_ptr<const Scripts> source;
    { std::lock_guard guard(configuration_mutex); source = configured; }
    if (!source) return {};
    return std::shared_ptr<LuaServer>(new LuaServer(std::make_unique<Impl>(std::move(source))));
}
LuaValue LuaServer::status() {
    std::lock_guard guard(configuration_mutex);
    return {{"enabled", static_cast<bool>(configured)}, {"generation", configured ? configured->generation : 0},
        {"modules", configured ? configured->sources.size() : 0}, {"api_version", 1}};
}
LuaValue LuaServer::call(const std::string& event, const LuaValue& request, const LuaBindings& bindings) {
    auto& runtime = *impl_; std::lock_guard guard(runtime.mutex);
    const auto top = lua_gettop(runtime.state);
    const auto* previous = runtime.bindings;
    runtime.bindings = &bindings;
    if (!previous) runtime.remaining = instruction_limit;
    try {
        lua_rawgeti(runtime.state, LUA_REGISTRYINDEX, runtime.module);
        lua_getfield(runtime.state, -1, "dispatch");
        if (!lua_isfunction(runtime.state, -1)) throw std::runtime_error("lua_dispatch_missing");
        protected_push(runtime.state, LuaValue(event)); protected_push(runtime.state, request);
        runtime.checked_call(2, 1);
        auto result = read_value(runtime.state, -1);
        lua_settop(runtime.state, top); runtime.bindings = previous; return result;
    } catch (...) { lua_settop(runtime.state, top); runtime.bindings = previous; throw; }
}
}

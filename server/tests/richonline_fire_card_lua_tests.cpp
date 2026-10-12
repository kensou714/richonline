#include "lua_server.hpp"

#include <filesystem>
#include <stdexcept>
#include <string>

using namespace richnet;

namespace {
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

struct Scenario {
    int prepared = 0;
    int ground_batches = 0;
    int logged = 0;
    bool placeable = false;
    LuaValue objects;

    LuaBindings bindings() {
        return {
            {"card.prepare", [this](const LuaValue& args) {
                check(args == LuaValue{{"card", 1183}}, "wrong_card_prepared");
                ++prepared;
                return LuaValue{{"slot", 1}, {"bank", 0}};
            }},
            {"game.snapshot", [](const LuaValue&) { return LuaValue{{"can_act", true}}; }},
            {"research.traps", [](const LuaValue& args) {
                check(args == LuaValue{{"kind", "fire"}}, "wrong_trap_rules");
                return LuaValue{{"fire_radius", 1}, {"fire_rounds", 3}};
            }},
            {"map.info", [](const LuaValue&) { return LuaValue{{"width", 3}, {"height", 3}}; }},
            {"map.cell", [this](const LuaValue& args) {
                const auto position = args.at("position").get<int>();
                check(position >= 0 && position < 9, "invalid_cell_query");
                return LuaValue{{"walkable", placeable && position == 5},
                    {"ground_visible", true}, {"placement_occupied", false},
                    {"ground_occupied", false}, {"static_type", 0}};
            }},
            {"ground.prepare_batch", [this](const LuaValue& args) {
                ++ground_batches;
                objects = args.at("objects");
                return LuaValue{};
            }},
            {"log", [this](const LuaValue& args) {
                check(args.at("event") == "fire_card_plan" && args.at("center") == 4 &&
                    args.at("placed") == 1, "wrong_fire_plan_log");
                ++logged;
                return LuaValue{};
            }}
        };
    }
};

LuaValue fire_request() {
    const std::string payload{"\x9d\x00\x69\x45\x01\x00\x04\x00", 8};
    return LuaValue{{"opcode", 157}, {"game_id", 0x1234}, {"actor", 0}, {"payload", payload}};
}
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    LuaServer::configure(std::filesystem::path(argv[1]));
    const auto runtime = LuaServer::create();
    check(static_cast<bool>(runtime), "lua_runtime_missing");

    Scenario empty;
    bool rejected = false;
    try { static_cast<void>(runtime->call("game.action", fire_request(), empty.bindings())); }
    catch (const std::runtime_error&) { rejected = true; }
    check(rejected && empty.prepared == 1 && empty.ground_batches == 0 && empty.logged == 0,
        "empty_fire_area_was_accepted_or_mutated");

    Scenario available;
    available.placeable = true;
    const auto response = runtime->call("game.action", fire_request(), available.bindings());
    check(response.is_array() && response.size() == 1 && response[0].is_string() &&
        response[0].get<std::string>() == std::string{"\xed\x40\x34\x12\x01\x00\x04\x00", 8},
        "fire_reply_wrong");
    check(available.prepared == 1 && available.ground_batches == 1 && available.logged == 1 &&
        available.objects == LuaValue::array({{{"position", 5}, {"npc", 26}, {"byte7", 0}, {"byte8", 3}}}),
        "fire_ground_plan_wrong");
}

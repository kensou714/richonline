#include "original_movement_bomb.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class F> void rejects(F action, std::string_view code) {
    try { action(); } catch (const CodecError& error) { check(error.what() == code,"wrong bomb rejection"); return; }
    throw std::runtime_error("missing bomb rejection");
}
void transfer_order_and_filters() {
    const OriginalBombRoster input{0,true,OriginalAttachedBomb{4,7},
        {{4,1,true,-1,-1,{}},{1,1,false,-1,-1,{}},{2,1,true,0,-1,{}},{3,1,true,-1,0,{}},
         {5,1,true,-1,-1,OriginalAttachedBomb{1,2}}}};
    const auto result = predict_original_bombs(input,{{1,3},{2,3}});
    check(result.transfers.size() == 1 && result.transfers[0].step == 1 && result.transfers[0].target == 4,
        "first active eligible ascending slot receives bomb");
    check(!result.after.attached && result.after.others[0].bomb == OriginalAttachedBomb{3,7} &&
        result.after.others[4].bomb == OriginalAttachedBomb{1,2},"decrement before exchange, later targets untouched");
    check(input.attached == OriginalAttachedBomb{4,7} && !input.others[0].bomb,"prediction preserves world input");
    auto reordered = input; std::reverse(reordered.others.begin(),reordered.others.end());
    check(predict_original_bombs(reordered,{{1,3}}).transfers.at(0).target == 4,"storage order cannot change slot priority");
}
void swapped_count_and_repeat() {
    const OriginalBombRoster input{0,true,OriginalAttachedBomb{7,3},{{1,1,true,-1,-1,OriginalAttachedBomb{2,-7}}}};
    const auto result = predict_original_bombs(input,{{1,3},{2,3},{1,1},{0,1}});
    check(result.explosion_step == 3 && result.transfers.size() == 1 && !result.after.attached && result.exploded_owner == -7,
        "newly received countdown waits until next physical step; expiry precedes transfer on repeated tile");
    check(result.after.others[0].bomb == OriginalAttachedBomb{6,3},"owner and decremented count transferred together");
    const auto late = predict_original_bombs({0,true,OriginalAttachedBomb{1,3},{{1,1,true,-1,-1,{}}}},{{1,3}});
    check(late.explosion_step == 1 && late.transfers.empty() && !late.after.others[0].bomb,
        "expiry prevents same-tile transfer");
}
void no_bomb_and_special_game() {
    const OriginalBombRoster absent{0,true,{},{{1,1,true,-1,-1,OriginalAttachedBomb{3,1}}}};
    const auto ignored = predict_original_bombs(absent,{{1,3}});
    check(ignored.transfers.empty() && !ignored.after.attached,"unarmed mover does not take other actor bomb");
    const OriginalBombRoster special{0,false,OriginalAttachedBomb{1,8},{{1,1,true,-1,-1,OriginalAttachedBomb{2,9}}}};
    const auto swapped = predict_original_bombs(special,{{1,3},{2,3}});
    check(!swapped.explosion_step && swapped.transfers.size() == 1 && swapped.after.attached == OriginalAttachedBomb{2,9} &&
        swapped.after.others[0].bomb == OriginalAttachedBomb{1,8},"special game skips decrement but retains transfer");
}
void invalid_bombs() {
    rejects([] { validate_original_bombs({0,true,OriginalAttachedBomb{0,0},{}}); },"original_movement_bomb_count_invalid");
    rejects([] { validate_original_bombs({0,true,OriginalAttachedBomb{128,0},{}}); },"original_movement_bomb_count_invalid");
    rejects([] { validate_original_bombs({0,true,{},{{0,1,true,-1,-1,{}}}}); },"original_movement_bomb_slot_duplicate");
    rejects([] { validate_original_bombs({0,true,{},{{1,1,true,-1,-1,{}},{1,2,true,-1,-1,{}}}}); },"original_movement_bomb_slot_duplicate");
}
}
int main() {
    try {
        transfer_order_and_filters(); swapped_count_and_repeat(); no_bomb_and_special_game(); invalid_bombs();
        std::cout << "PASS original bomb decrement/transfer priority, status filters, repeat visits and special-game path.\n"; return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}

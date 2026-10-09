#include "richonline_room_directory.hpp"

#include <algorithm>
#include <bit>
#include <iostream>
#include <limits>
#include <string_view>

namespace {
using namespace richnet;
void require(bool value, std::string_view code) { if (!value) throw std::runtime_error(std::string(code)); }
template<class Action> void rejects(Action action, std::string_view expected) {
    try { action(); } catch (const CodecError& error) { require(error.what() == expected, "wrong_rejection"); return; }
    throw std::runtime_error("expected_rejection");
}
RichonlineRoomDescription description() {
    RichonlineRoomDescription result{};
    result.record[0] = 'r'; result.record[1] = 0; result.record[76] = 's'; result.record[77] = 0;
    result.record[124] = 1;
    result.record[40] = 2; result.record[72] = 2;
    return result;
}
Bytes create_payload() {
    auto data = description().record;
    return {data.begin(), data.end()};
}
Bytes join_payload(std::uint32_t key, std::uint32_t slot) {
    Bytes body; append_le(body, key, 4); append_le(body, slot, 4); append_le(body, 1, 4); return body;
}
void put(Bytes& body, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) body.at(offset + i) = static_cast<std::uint8_t>(value >> (i * 8));
}
void put64(Bytes& body, std::size_t offset, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i) body.at(offset + i) = static_cast<std::uint8_t>(value >> (i * 8));
}
Bytes edit_payload(std::uint32_t key, std::uint32_t owner = 70, std::uint32_t slot = 0) {
    Bytes body; append_le(body, key, 4); const auto data = create_payload(); body.insert(body.end(), data.begin(), data.end());
    put(body, 4 + 48, 0xffffffffU); put(body, 4 + 60, owner); put(body, 4 + 64, slot);
    return body;
}
void enter(RichonlineRoomDirectory& directory, std::uint64_t connection, std::uint32_t actor) {
    Bytes profile(272);
    for (std::size_t i = 0; i < 4; ++i) profile[i] = static_cast<std::uint8_t>(actor >> (i * 8));
    static_cast<void>(directory.enter(connection, actor, {7, profile}));
}
void creation_join_prepare_cancel_leave_cycle() {
    RichonlineRoomDirectory directory({0x12345678, 8});
    enter(directory, 10, 101);
    enter(directory, 11, 202);
    const auto created = directory.receive(10, 101, {3, create_payload()});
    require(created.size() == 2 && created[0].recipient == 10 && created[0].frame.wire_type == 10 &&
            created[0].frame.payload.size() == 128, "create_response_wrong");
    require(read_le(View(created[0].frame.payload).subspan(76, 4)) == 2, "selected_count_not_sent_as_object28");
    require(created[1].recipient == 11 && created[1].frame.wire_type == 10,
            "idle_peer_missing_room_or_owner");
    require(directory.room_count() == 1 && directory.peer_count(1) == 1, "create_state_wrong");
    const auto joined = directory.receive(11, 202, {4, join_payload(1, 1)});
    require(joined.size() == 2 && joined[0].recipient == 10 && joined[1].recipient == 11 &&
            joined[0].frame.wire_type == 12 && joined[1].frame.wire_type == 12, "join_broadcast_wrong");
    require(directory.peer_count(1) == 2, "join_state_wrong");
    const auto ready = directory.receive(10, 101, {5, {}});
    require(ready.size() == 2 && std::all_of(ready.begin(), ready.end(), [](const auto& item) { return item.frame.wire_type == 13 && item.frame.payload.size() == 8; }), "prepare_broadcast_wrong");
    const auto cancelled = directory.receive(10, 101, {60, {}});
    require(cancelled.size() == 2 && cancelled[0].frame.wire_type == 96 && cancelled[1].frame.wire_type == 96,
            "cancel_broadcast_wrong");
    const auto left = directory.receive(11, 202, {6, {1,0,0,0}});
    require(left.size() == 2 && left[0].recipient == 10 && left[1].recipient == 11 && left[1].frame.wire_type == 14 &&
            directory.peer_count(1) == 1, "leave_cleanup_wrong");
    const auto gone = directory.disconnect(10);
    require(gone.size() == 3 && gone[0].recipient == 11 && gone[0].frame.wire_type == 14 && gone[1].frame.wire_type == 57 &&
            gone[2].frame.wire_type == 55 &&
            directory.room_count() == 0, "disconnect_cleanup_wrong");
}
void ready_snapshot_keeps_extension_and_pending_blocks_join() {
    RichonlineRoomDirectory directory({7, 8});
    enter(directory, 1, 10); enter(directory, 2, 20);
    auto body = create_payload();
    body[32] = 0x40; body[120] = 88;
    body.insert(body.end(), 88, 0xa5);
    static_cast<void>(directory.receive(1, 10, {3, body}));
    require(!directory.ready_game(1), "unready_snapshot_returned");
    static_cast<void>(directory.receive(1, 10, {5, {}}));
    const auto snapshot = directory.ready_game(1);
    require(snapshot && snapshot->participants.size() == 1 && snapshot->participants[0].connection == 1 &&
            snapshot->description.extension == Bytes(88, 0xa5), "ready_snapshot_lost_identity_or_extension");
    directory.set_game_pending(1, true);
    rejects([&] { directory.receive(2, 20, {4, join_payload(1, 1)}); }, "richonline_room_game_admission_pending");
    require(!directory.ready_game(1), "duplicate_pending_start_returned");
    const auto reset = directory.game_finished(1);
    require(reset.size()==4&&reset[0].frame.wire_type==96&&reset[1].frame.wire_type==96&&
        reset[2].recipient==1&&reset[3].recipient==2&&reset[2].frame.wire_type==58&&reset[3].frame.wire_type==58&&
        reset[2].frame.payload==Bytes({1,0,0,0})&&!directory.ready_game(1),"finished_game_not_reset");
    require(directory.room_count()==1&&directory.peer_count(1)==1&&directory.game_finished(1).empty(),"finished_room_removed_or_repeated");
    static_cast<void>(directory.receive(2, 20, {4, join_payload(1, 1)}));
}
void selected_count_comes_from_native_create_not_policy_default() {
    RichonlineRoomDirectory directory({7, 8});
    enter(directory, 1, 10); enter(directory, 2, 20);
    auto body = create_payload();
    body[36] = 2; body[40] = 1; body[72] = 1;
    const auto created = directory.receive(1, 10, {3, body});
    require(read_le(View(created.front().frame.payload).subspan(76, 4)) == 1, "solo_count_overwritten_by_policy");
    rejects([&] { directory.receive(2, 20, {4, join_payload(1, 1)}); }, "richonline_room_full");
    body[36] = 0;
    rejects([&] { directory.receive(2, 20, {3, body}); }, "richonline_room_selected_player_count_invalid");
}
void character_change_persists_before_broadcast_and_updates_late_snapshot() {
    RichonlineRoomDirectory directory({7,8});
    enter(directory,1,10); enter(directory,2,20);
    static_cast<void>(directory.receive(1,10,{3,create_payload()}));
    int persisted=0;
    const auto changed=directory.select_character(1,8,[&] { ++persisted; });
    require(persisted==1 && changed.size()==2 && changed[0].frame.wire_type==18 &&
        read_le(View(changed[0].frame.payload).subspan(4,4))==8,"character_change_not_committed");
    rejects([&] { directory.select_character(1,9,[&] { ++persisted; }); },"richonline_character_selection_invalid");
    rejects([&] { directory.select_character(1,2,[] { throw CodecError("persistence_failed"); }); },"persistence_failed");
    Bytes profile(272); profile[0]=30;
    const auto late=directory.enter(3,30,{7,profile});
    const auto found=std::find_if(late.begin(),late.end(),[](const auto& dispatch) {
        return dispatch.recipient==3 && dispatch.frame.wire_type==7 && read_le(View(dispatch.frame.payload).first(4))==10;
    });
    require(found!=late.end() && read_le(View(found->frame.payload).subspan(40,4))==8,"late_character_snapshot_stale");
    static_cast<void>(directory.receive(1,10,{5,{}}));
    rejects([&] { directory.select_character(1,2,[&] { ++persisted; }); },"richonline_character_selection_while_ready");
    require(persisted==1,"ready_character_mutation_persisted");
}
void rejects_unknown_and_malformed_requests() {
    RichonlineRoomDirectory directory({9, 8});
    enter(directory, 1, 2); enter(directory, 2, 3);
    rejects([&] { directory.receive(1, 2, {5, {}}); }, "richonline_room_peer_not_in_room");
    rejects([&] { directory.receive(1, 2, {3, Bytes(127)}); }, "richonline_room_description_truncated");
    static_cast<void>(directory.receive(1, 2, {3, create_payload()}));
    rejects([&] { directory.receive(2, 3, {4, join_payload(99, 1)}); }, "richonline_room_not_found");
    rejects([&] { directory.receive(1, 2, {6, {0,0,0,0}}); }, "richonline_room_leave_payload_invalid");
    rejects([&] { directory.receive(1, 2, {5, {0}}); }, "richonline_room_prepare_payload_invalid");
    rejects([&] { directory.receive(1, 2, {42, {}}); }, "richonline_room_request_unsupported");
}
void edit_replaces_description_and_preserves_members() {
    RichonlineRoomDirectory directory({9, 8});
    enter(directory, 7, 70); enter(directory, 8, 80);
    static_cast<void>(directory.receive(7, 70, {3, create_payload()}));
    const auto edited = directory.receive(7, 70, {23, edit_payload(1)});
    require(edited.size() == 2 && edited[0].recipient == 7 && edited[0].frame.wire_type == 26, "edit_response_wrong");
    require(directory.peer_count(1) == 1, "edit_removed_member");
    rejects([&] { directory.receive(8, 80, {23, edit_payload(1)}); }, "richonline_room_peer_not_in_room");
    auto changed = edit_payload(1);
    changed[4] = 'x';
    rejects([&] { directory.receive(7, 70, {23, changed}); }, "richonline_room_metadata_update_unproven");
}
void owner_leave_transfers_owner_and_disconnect_removes_only_departing_profile() {
    RichonlineRoomDirectory directory({7, 8});
    enter(directory, 1, 10); enter(directory, 2, 20); enter(directory, 3, 30);
    static_cast<void>(directory.receive(1, 10, {3, create_payload()}));
    static_cast<void>(directory.receive(2, 20, {4, join_payload(1, 2)}));
    const auto left = directory.disconnect(1);
    require(left.size() == 4 && left[0].frame.wire_type == 14 && read_le(View(left[0].frame.payload).subspan(8, 4)) == 20,
            "owner_not_transferred");
    require(std::count_if(left.begin(), left.end(), [](const auto& item) { return item.frame.wire_type == 55; }) == 2,
            "remote_profile_not_removed");
    require(std::none_of(left.begin(), left.end(), [](const auto& item) { return item.recipient == 1 || item.frame.wire_type == 57; }),
            "live_room_or_departing_peer_received_wrong_delete");
    const auto edited = directory.receive(2, 20, {23, edit_payload(1, 20)});
    require(edited.size() == 2, "new_owner_cannot_edit");
}
void native_edit_uses_received_identity_normalized_fields_and_c_string_content() {
    RichonlineRoomDirectory directory({7, 8});
    enter(directory, 1, 10);
    auto created_body = create_payload();
    put(created_body, 32, 0x1081); // create-only flags and receiver-ignored 0x1000.
    put(created_body, 48, 123); put(created_body, 52, 0); put(created_body, 56, 0x3ff00000);
    put(created_body, 60, 0xffffffffU); put(created_body, 64, 0xffffffffU);
    put(created_body, 108, 11); put(created_body, 112, 22); put(created_body, 116, 33);
    const auto created = directory.receive(1, 10, {3, created_body});
    require(read_le(View(created.front().frame.payload).subspan(68, 4)) == 10, "create_identity_missing");
    auto edit = edit_payload(1, 10);
    std::fill(edit.begin() + 6, edit.begin() + 36, 0xa5);
    std::fill(edit.begin() + 82, edit.begin() + 112, 0xb6);
    put(edit, 124, 88); edit.insert(edit.end(), 88, 0xcc);
    const auto result = directory.receive(1, 10, {23, edit});
    require(result.size() == 1 && result.front().frame.wire_type == 26 &&
            result.front().frame.payload.size() == 220, "native_edit_not_accepted");
    static_cast<void>(directory.receive(1, 10, {5, {}}));
    const auto snapshot = directory.ready_game(1);
    require(snapshot && snapshot->description.extension == Bytes(88, 0xcc), "edited_blob_not_stored");
    Bytes profile(272); profile[0] = 20;
    const auto delivered = directory.enter(2, 20, {7, profile});
    const auto room = std::find_if(delivered.begin(), delivered.end(), [](const auto& item) { return item.frame.wire_type == 5; });
    require(room != delivered.end() && room->frame.payload.size() == 224 &&
            read_le(View(room->frame.payload).subspan(128, 4)) == 88, "added_blob_missing_from_late_snapshot");
}
void native_edit_uses_old_blob_flag_and_snapshot_slot_after_owner_transfer() {
    RichonlineRoomDirectory directory({7, 8});
    enter(directory, 1, 10); enter(directory, 2, 20);
    auto body = create_payload(); body[32] = 0x40; body[120] = 88; body.insert(body.end(), 88, 0xa5);
    static_cast<void>(directory.receive(1, 10, {3, body}));
    static_cast<void>(directory.receive(2, 20, {4, join_payload(1, 2)}));
    static_cast<void>(directory.disconnect(1));
    auto edit = edit_payload(1, 20, 0); put(edit, 36, 0x40);
    const auto updated = directory.receive(2, 20, {23, edit});
    require(updated.size() == 1 && updated.front().frame.payload.size() == 132, "old_blob_flag_rejected");
    const auto observer = directory.enter(3, 30, {7, [] { Bytes value(272); value[0] = 30; return value; }()});
    const auto room = std::find_if(observer.begin(), observer.end(), [](const auto& item) { return item.frame.wire_type == 5; });
    require(room != observer.end() && room->frame.payload.size() == 128 &&
            read_le(View(room->frame.payload).subspan(72, 4)) == 0, "late_snapshot_blob_or_slot_wrong");
    static_cast<void>(directory.receive(3, 30, {4, join_payload(1, 1)}));
    static_cast<void>(directory.disconnect(2));
    const auto late_edit = directory.receive(3, 30, {23, edit_payload(1, 30, 0)});
    require(late_edit.size() == 1, "late_owner_received_slot_lost");
}
void effective_optional_fields_are_preserved_and_changes_do_not_mutate_room() {
    RichonlineRoomDirectory directory({7, 8}); enter(directory, 1, 10);
    auto body = create_payload();
    put(body, 32, 0x300); put(body, 48, 123); put(body, 56, 0x3ff00000);
    static_cast<void>(directory.receive(1, 10, {3, body}));
    auto edit = edit_payload(1, 10);
    put(edit, 36, 0x300); put(edit, 52, 123); put(edit, 60, 0x3ff00000);
    require(directory.receive(1, 10, {23, edit}).front().frame.wire_type == 26, "effective_optional_fields_lost");
    for (const std::size_t offset : {std::size_t{36}, std::size_t{52}, std::size_t{60}, std::size_t{64}, std::size_t{68}, std::size_t{112}}) {
        auto changed = edit; changed[offset] ^= 1;
        put(changed, 124, 1); changed.push_back(0xab);
        rejects([&] { directory.receive(1, 10, {23, changed}); }, offset == 36 ?
                "richonline_room_flags_unsupported" : "richonline_room_metadata_update_unproven");
    }
    static_cast<void>(directory.receive(1, 10, {5, {}}));
    const auto snapshot = directory.ready_game(1);
    require(snapshot && snapshot->description.extension.empty() && snapshot->description.field(48) == 123 &&
            snapshot->description.field(56) == 0x3ff00000, "rejected_metadata_mutated_room");
}
void room_keys_wrap_inside_capacity_and_idle_disconnect_is_safe() {
    RichonlineRoomDirectory directory({7, 3});
    enter(directory, 1, 10); enter(directory, 2, 20); enter(directory, 3, 30);
    static_cast<void>(directory.receive(1, 10, {3, create_payload()}));
    static_cast<void>(directory.receive(2, 20, {3, create_payload()}));
    static_cast<void>(directory.receive(3, 30, {3, create_payload()}));
    require(directory.peer_count(0) == 1 && directory.peer_count(1) == 1 && directory.peer_count(2) == 1, "keys_not_bounded");
    static_cast<void>(directory.receive(1, 10, {6, {1,0,0,0}}));
    static_cast<void>(directory.receive(1, 10, {3, create_payload()}));
    require(directory.room_count() == 3 && directory.peer_count(1) == 1, "key_hole_not_reused");
    require(directory.disconnect(99).empty(), "unknown_disconnect_not_idempotent");
}
void refresh_profile_preserves_unrelated_state_and_rejects_stale_updates() {
    RichonlineRoomDirectory directory({7, 8});
    Bytes original(272);
    put(original, 0, 10);
    put(original, 40, 2);
    put(original, 96, 0x12345678);
    original[112] = 'A';
    std::fill(original.begin() + 144, original.end(), 0xa5);
    static_cast<void>(directory.enter(1, 10, {7, original}));
    static_cast<void>(directory.receive(1, 10, {3, create_payload()}));
    const Frame expected = directory.current_profile(1, 10);
    require(read_le(View(expected.payload).subspan(12, 4)) == 1 &&
            read_le(View(expected.payload).subspan(44, 4)) == 0, "room_location_missing_from_profile");
    Frame update{19, Bytes(expected.payload.begin(), expected.payload.begin() + 144)};
    put(update.payload, 24, 9);
    put(update.payload, 28, 8);
    put(update.payload, 32, 7);
    put(update.payload, 52, 42);
    put64(update.payload, 80, std::bit_cast<std::uint64_t>(123.5));
    put64(update.payload, 88, std::bit_cast<std::uint64_t>(456.25));
    put(update.payload, 104, 10000);
    put(update.payload, 108, 3);

    rejects([&] { directory.current_profile(2, 10); }, "richonline_room_actor_not_registered");
    rejects([&] { directory.current_profile(1, 20); }, "richonline_room_actor_not_registered");
    rejects([&] { directory.refresh_profile(2, 10, expected, update); }, "richonline_room_actor_not_registered");
    rejects([&] { directory.refresh_profile(1, 20, expected, update); }, "richonline_room_actor_not_registered");
    auto bad_expected = expected;
    bad_expected.wire_type = 19;
    rejects([&] { directory.refresh_profile(1, 10, bad_expected, update); }, "richonline_room_expected_profile_invalid");
    bad_expected = expected; bad_expected.payload.pop_back();
    rejects([&] { directory.refresh_profile(1, 10, bad_expected, update); }, "richonline_room_expected_profile_invalid");
    bad_expected = expected; put(bad_expected.payload, 0, 20);
    rejects([&] { directory.refresh_profile(1, 10, bad_expected, update); }, "richonline_room_expected_profile_invalid");
    bad_expected = expected; bad_expected.payload[200] ^= 1;
    rejects([&] { directory.refresh_profile(1, 10, bad_expected, update); }, "richonline_room_profile_stale");
    for (const std::size_t offset : std::array<std::size_t, 20>{0, 4, 8, 12, 16, 20, 36, 40, 44,
                                                                 48, 56, 60, 64, 68, 72, 76, 96, 100, 112, 143}) {
        auto bad = update; bad.payload[offset] ^= 1;
        rejects([&] { directory.refresh_profile(1, 10, expected, bad); }, offset == 0 ?
                "richonline_room_profile_refresh_invalid" : "richonline_room_profile_refresh_field_unproven");
    }
    auto bad = update; bad.wire_type = 23;
    rejects([&] { directory.refresh_profile(1, 10, expected, bad); }, "richonline_room_profile_refresh_invalid");
    bad = update; bad.payload.pop_back();
    rejects([&] { directory.refresh_profile(1, 10, expected, bad); }, "richonline_room_profile_refresh_invalid");
    bad = update; std::fill(bad.payload.begin() + 112, bad.payload.end(), 0x41);
    rejects([&] { directory.refresh_profile(1, 10, expected, bad); }, "richonline_room_profile_refresh_values_invalid");
    bad = update; put64(bad.payload, 88, std::bit_cast<std::uint64_t>(std::numeric_limits<double>::infinity()));
    rejects([&] { directory.refresh_profile(1, 10, expected, bad); }, "richonline_room_profile_refresh_values_invalid");
    require(directory.current_profile(1, 10).payload == expected.payload, "invalid_refresh_mutated_cache");

    directory.refresh_profile(1, 10, expected, update);
    const auto refreshed = directory.current_profile(1, 10);
    require(refreshed.wire_type == 7 && refreshed.payload.size() == 272, "refresh_changed_full_profile_shape");
    for (std::size_t offset = 0; offset < 272; ++offset) {
        const bool mutable_field = (offset >= 24 && offset < 36) || (offset >= 52 && offset < 56) ||
                                   (offset >= 80 && offset < 96) || (offset >= 104 && offset < 112);
        require(refreshed.payload[offset] == (mutable_field ? update.payload[offset] : expected.payload[offset]),
                "refresh_modified_wrong_byte");
    }
    rejects([&] { directory.refresh_profile(1, 10, expected, update); }, "richonline_room_profile_stale");
    Bytes late(272); put(late, 0, 30);
    const auto delivered = directory.enter(3, 30, {7, late});
    const auto found = std::find_if(delivered.begin(), delivered.end(), [](const auto& item) {
        return item.recipient == 3 && item.frame.wire_type == 7 && read_le(View(item.frame.payload).first(4)) == 10;
    });
    require(found != delivered.end() && found->frame.payload == refreshed.payload, "late_observer_received_stale_profile");
    auto next_update = update; put(next_update.payload, 24, 10);
    static_cast<void>(directory.select_character(1, 3, [] {}));
    rejects([&] { directory.refresh_profile(1, 10, refreshed, next_update); }, "richonline_room_profile_stale");
    require(read_le(View(directory.current_profile(1, 10).payload).subspan(40, 4)) == 3,
            "stale_refresh_overwrote_character");
}
}
int main() {
    try {
        creation_join_prepare_cancel_leave_cycle();
        rejects_unknown_and_malformed_requests();
        edit_replaces_description_and_preserves_members();
        owner_leave_transfers_owner_and_disconnect_removes_only_departing_profile();
        room_keys_wrap_inside_capacity_and_idle_disconnect_is_safe();
        ready_snapshot_keeps_extension_and_pending_blocks_join();
        selected_count_comes_from_native_create_not_policy_default();
        character_change_persists_before_broadcast_and_updates_late_snapshot();
        native_edit_uses_received_identity_normalized_fields_and_c_string_content();
        native_edit_uses_old_blob_flag_and_snapshot_slot_after_owner_transfer();
        effective_optional_fields_are_preserved_and_changes_do_not_mutate_room();
        refresh_profile_preserves_unrelated_state_and_rejects_stale_updates();
        std::cout << "richonline room directory tests PASS\n";
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n'; return 1;
    }
}

#include "richonline_room_protocol.hpp"

#include <algorithm>
#include <iostream>
#include <string_view>

namespace {
using namespace richnet;
void check(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
template<class Action> void rejects(Action action, std::string_view expected) {
    try { action(); }
    catch (const CodecError& error) { check(error.what() == expected, "unexpected_rejection"); return; }
    throw std::runtime_error("expected_rejection");
}
void put(Bytes& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) bytes.at(offset + i) = static_cast<std::uint8_t>(value >> (8 * i));
}
Bytes request(bool extension) {
    Bytes bytes(128, 0);
    bytes[0] = 'R';
    put(bytes, 32, extension ? 0xc0U : 0x80U);
    put(bytes, 40, 2); put(bytes, 44, 4);
    put(bytes, 48, 0xffffffffU); put(bytes, 60, 0xffffffffU); put(bytes, 64, 0xffffffffU);
    put(bytes, 68, 2); put(bytes, 72, 2);
    bytes[108] = 0xa1; bytes[112] = 0xb2; bytes[116] = 0xc3;
    put(bytes, 124, 1);
    if (extension) {
        const Bytes opaque{0xaa, 0xbb, 0xcc, 0xdd, 0xee};
        put(bytes, 120, static_cast<std::uint32_t>(opaque.size()));
        bytes.insert(bytes.end(), opaque.begin(), opaque.end());
    }
    return bytes;
}
void length_and_marker_are_enforced_before_extension_reads() {
    auto bytes = request(true);
    const auto parsed = decode_richonline_room_create(bytes);
    check(parsed.extension == Bytes({0xaa,0xbb,0xcc,0xdd,0xee}), "opaque_extension_changed");
    bytes.pop_back();
    rejects([&] { decode_richonline_room_create(bytes); }, "richonline_room_data_length_mismatch");
    bytes = request(false); put(bytes, 124, 0);
    rejects([&] { decode_richonline_room_create(bytes); }, "richonline_room_data_marker_invalid");
    bytes = request(false); bytes.resize(127);
    rejects([&] { decode_richonline_room_create(bytes); }, "richonline_room_description_truncated");
    bytes = request(true); put(bytes, 32, 0x80);
    rejects([&] { decode_richonline_room_create(bytes); }, "richonline_room_data_flag_mismatch");
    bytes = request(false); put(bytes, 32, 0x80000000U);
    rejects([&] { decode_richonline_room_create(bytes); }, "richonline_room_flags_unsupported");
}
void fixed_strings_require_termination_and_edit_preserves_dword_tag() {
    auto bytes = request(false);
    std::fill_n(bytes.begin(), 32, 0xa1);
    rejects([&] { decode_richonline_room_create(bytes); }, "richonline_room_name_unterminated");
    bytes = request(false);
    std::fill_n(bytes.begin() + 76, 32, 0xb2);
    rejects([&] { decode_richonline_room_create(bytes); }, "richonline_room_secondary_name_unterminated");
    bytes = request(true); put(bytes, 32, 0x40);
    bytes.insert(bytes.begin(), {7,0xa1,0xb2,0xc3});
    const auto edit = decode_richonline_room_edit(bytes);
    check(edit.tag == 0xc3b2a107U, "edit_tag_truncated_to_byte");
    check(edit.description.extension == Bytes({0xaa,0xbb,0xcc,0xdd,0xee}), "edit_extension_offset_wrong");
}
void response_uses_server_identity_and_does_not_copy_client_slot_sentinels() {
    const auto request_bytes = request(true);
    const auto parsed = decode_richonline_room_create(request_bytes);
    const auto response = richonline_room_record(10, parsed, {3,0xdeadbeefU,25,0,2});
    const View bytes(response.payload);
    check(response.wire_type == 10 && bytes.size() == 141, "response_size_wrong");
    check(read_le(bytes.first(4)) == 3 && read_le(bytes.subspan(4,4)) == 0xdeadbeefU, "response_prefix_wrong");
    check(read_le(bytes.subspan(68,4)) == 25, "local_self_predicate_wrong");
    check(read_le(bytes.subspan(72,4)) == 0, "local_slot_wrong");
    check(read_le(bytes.subspan(76,4)) == 2, "opaque_object28_wrong");
    check(read_le(bytes.subspan(80,4)) == 2, "source_capacity_mapping_wrong");
    check(bytes[116] == 0xa1 && bytes[120] == 0xb2 && bytes[124] == 0xc3, "opaque_reserved_changed");
    check(std::equal(bytes.begin()+136,bytes.end(),parsed.extension.begin()), "response_extension_changed");
    const auto empty = richonline_room_record(5, decode_richonline_room_create(request(false)), {3,0xdeadbeefU,25,0,2});
    check(empty.payload.size() == 128, "absent_extension_has_unread_suffix");
}
void edit_extension_flag_describes_old_blob_not_new_blob() {
    auto added = request(true); put(added, 32, 0); added.insert(added.begin(), {1,0,0,0});
    check(decode_richonline_room_edit(added).description.extension.size() == 5, "empty_old_blob_cannot_gain_extension");
    auto removed = request(false); put(removed, 32, 0x40); removed.insert(removed.begin(), {1,0,0,0});
    check(decode_richonline_room_edit(removed).description.extension.empty(), "existing_old_blob_cannot_be_removed");
}
}
int main() {
    try {
        length_and_marker_are_enforced_before_extension_reads();
        fixed_strings_require_termination_and_edit_preserves_dword_tag();
        response_uses_server_identity_and_does_not_copy_client_slot_sentinels();
        edit_extension_flag_describes_old_blob_not_new_blob();
        std::cout << "PASS Richonline room record boundaries and identity mapping\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}

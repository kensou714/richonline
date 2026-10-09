#include "richonline_game_redirect.hpp"
#include "pending_game_admissions.hpp"

#include <iostream>
#include <stdexcept>

namespace {
using namespace richnet;
void check(bool ok, const char* reason) { if (!ok) throw std::runtime_error(reason); }
void redirect_bytes_match_new_client_reads_and_admission_echo() {
    const RichonlineGameRedirect redirect{{127,0,0,1}, 18602, 0x12345678U, {9,8,7,6,5,4,3,2}};
    const auto frame = encode_richonline_game_redirect(redirect);
    const Bytes expected{127,0,0,1,0xaa,0x48,0x78,0x56,0x34,0x12,9,8,7,6,5,4,3,2};
    check(frame.wire_type == 22 && frame.payload == expected, "redirect_address_port_or_unaligned_fields_wrong");
    const auto admission = richonline_expected_admission({0,3,25}, redirect);
    const Bytes client_echo{0,0,0,0,3,0,0,0,25,0,0,0,9,8,7,6,5,4,3,2,0x78,0x56,0x34,0x12};
    check(encode_game_admission(admission, ClientVersion::richonline).payload == client_echo, "admission_context_or_echo_wrong");
    PendingGameAdmissions registry;
    const auto now = AdmissionClock::now();
    registry.prepare({7,ClientVersion::richonline,admission,now+std::chrono::seconds(30)}, now);
    auto wrong = admission; wrong.id1 = 4;
    check(!registry.consume(ClientVersion::richonline,wrong,now), "redirect_ticket_cross_room_reuse");
    check(registry.consume(ClientVersion::richonline,admission,now) == 7, "redirect_ticket_not_bound_to_session");
    check(!registry.consume(ClientVersion::richonline,admission,now), "redirect_ticket_replay");
}
void redirect_rejects_unbound_tcp_port() {
    try { encode_richonline_game_redirect({{127,0,0,1},0,12,{1,2,3,4,5,6,7,8}}); }
    catch (const CodecError& error) { check(std::string(error.what()) == "richonline_game_redirect_port_invalid", "wrong_port_error"); return; }
    throw std::runtime_error("port_zero_was_advertised");
}
}
int main() {
    try {
        redirect_bytes_match_new_client_reads_and_admission_echo();
        redirect_rejects_unbound_tcp_port();
        std::cout << "PASS new-client redirect and single-use admission binding\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}

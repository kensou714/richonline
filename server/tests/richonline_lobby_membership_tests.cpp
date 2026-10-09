#include "richonline_lobby_membership.hpp"

#include <iostream>
#include <stdexcept>

using namespace richnet;
namespace {
void require(bool value,const char* name) { if (!value) throw std::runtime_error(name); }
template<class F> void rejects(F action,const char* name) {
    try { action(); } catch (const CodecError&) { return; }
    throw std::runtime_error(name);
}
Frame scalar(std::uint32_t wire,std::uint32_t value) {
    Bytes bytes;append_le(bytes,value,4);return {wire,std::move(bytes)};
}
Frame kick(std::uint32_t first,std::uint32_t room,std::uint32_t target,View reason) {
    Bytes bytes;
    for (const auto field:{first,room,target}) append_le(bytes,field,4);
    bytes.insert(bytes.end(),reason.begin(),reason.end());
    bytes.push_back(0);
    bytes.resize(44,0xA7);
    return {27,std::move(bytes)};
}
}
int main() {
    try {
        decode_richonline_leave_channel8(scalar(8,0));
        rejects([]{decode_richonline_leave_channel8({8,{}});},"empty_leave");
        rejects([]{decode_richonline_leave_channel8(scalar(8,1));},"leave_marker");
        rejects([]{decode_richonline_leave_channel8(scalar(9,0));},"leave_wrong_wire");
        const auto left=encode_richonline_left_channel16();
        require(left.wire_type==16 && left.payload.empty(),"leave_response");
        for (std::uint32_t team=0;team<4;++team) {
            require(decode_richonline_room_team9(scalar(9,team)).team==team,"teams");
            const auto changed=encode_richonline_room_team17(0x12345678,team);
            require(changed.wire_type==17 && changed.payload.size()==8 &&
                read_le(View(changed.payload).first(4))==0x12345678 &&
                read_le(View(changed.payload).subspan(4))==team,"team_response");
        }
        rejects([]{(void)decode_richonline_room_team9(scalar(9,4));},"team4");
        rejects([]{(void)decode_richonline_room_team9(scalar(9,0x100));},"team_full_dword");
        rejects([]{(void)encode_richonline_room_team17(1,0xffffffff);},"response_team_range");
        const Bytes control{1,1};
        auto request=kick(0x12345678,0x10203040,0x12345678,control);
        const auto parsed=decode_richonline_room_kick27(request);
        require(parsed.target_actor==0x12345678 && parsed.room==0x10203040 &&
            parsed.reason().size()==2 && parsed.reason()[0]==1 && parsed.reason()[1]==1 &&
            parsed.reason_slot[3]==0xA7,"kick_control_and_padding");
        const auto reply=encode_richonline_room_kicked27(17,18,parsed.room,parsed.target_actor,parsed.reason());
        require(reply.wire_type==27 && reply.payload.size()==19 &&
            read_le(View(reply.payload).first(4))==17 && read_le(View(reply.payload).subspan(4,4))==18 &&
            read_le(View(reply.payload).subspan(8,4))==parsed.room &&
            read_le(View(reply.payload).subspan(12,4))==parsed.target_actor &&
            reply.payload[16]==1 && reply.payload[17]==1 && reply.payload[18]==0,"kick_response_field_order");
        rejects([]{(void)decode_richonline_room_kick27(kick(1,2,3,{}));},"duplicate_target");
        request.payload[43]=0;request.payload[12]=0;
        require(decode_richonline_room_kick27(request).reason().empty(),"empty_reason");
        request.payload.resize(43);
        rejects([&]{(void)decode_richonline_room_kick27(request);},"short_reason_slot");
        request=kick(1,2,1,Bytes(31,0x81));
        require(decode_richonline_room_kick27(request).reason().size()==31,"full_reason");
        request.payload[43]=0x81;
        rejects([&]{(void)decode_richonline_room_kick27(request);},"missing_terminator");
        rejects([]{(void)encode_richonline_room_kicked27(1,2,3,4,Bytes(32,1));},"long_reason");
        rejects([]{(void)encode_richonline_room_kicked27(1,2,3,4,Bytes{1,0,2});},"embedded_nul");
        std::cout << "NEW lobby membership codec tests passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n';return 1; }
}

#include "richonline_lobby_membership.hpp"

#include <algorithm>

namespace richnet {
namespace {
void shape(const Frame& request,std::uint32_t wire,std::size_t size) {
    if (request.wire_type!=wire || request.payload.size()!=size)
        throw CodecError("richonline_lobby_membership_request_shape");
}
void team_range(std::uint32_t team) {
    // NEW73C0D0 controls2010..2013 send control-2010;6A40D0 also selects0..3.
    if (team>3) throw CodecError("richonline_room_team_range");
}
}

void decode_richonline_leave_channel8(const Frame& request) {
    shape(request,8,4);
    if (read_le(request.payload)!=0) throw CodecError("richonline_leave_channel_marker");
}
RichonlineRoomTeam9 decode_richonline_room_team9(const Frame& request) {
    shape(request,9,4);
    const auto team=read_le(request.payload);
    team_range(team);
    return {team};
}
View RichonlineRoomKick27::reason() const noexcept {
    const auto end=std::find(reason_slot.begin(),reason_slot.end(),std::uint8_t{0});
    return View(reason_slot).first(static_cast<std::size_t>(end-reason_slot.begin()));
}
RichonlineRoomKick27 decode_richonline_room_kick27(const Frame& request) {
    shape(request,27,44);
    const View bytes=request.payload;
    const auto target=read_le(bytes.first(4));
    if (target!=read_le(bytes.subspan(8,4))) throw CodecError("richonline_room_kick_target_mismatch");
    RichonlineRoomKick27 result{target,read_le(bytes.subspan(4,4)),{}};
    std::copy(bytes.begin()+12,bytes.end(),result.reason_slot.begin());
    if (std::find(result.reason_slot.begin(),result.reason_slot.end(),std::uint8_t{0})==result.reason_slot.end())
        throw CodecError("richonline_room_kick_reason_unterminated");
    return result;
}
Frame encode_richonline_left_channel16() { return {16,{}}; }
Frame encode_richonline_room_team17(std::uint32_t actor,std::uint32_t team) {
    team_range(team);
    Bytes payload;
    append_le(payload,actor,4);
    append_le(payload,team,4);
    return {17,std::move(payload)};
}
Frame encode_richonline_room_kicked27(std::uint32_t owner,std::uint32_t kicker,
    std::uint32_t room,std::uint32_t target,View reason) {
    if (reason.size()>31 || std::find(reason.begin(),reason.end(),std::uint8_t{0})!=reason.end())
        throw CodecError("richonline_room_kick_reason_invalid");
    Bytes payload;
    for (const auto field:{owner,kicker,room,target}) append_le(payload,field,4);
    payload.insert(payload.end(),reason.begin(),reason.end());
    payload.push_back(0);
    return {27,std::move(payload)};
}
} // namespace richnet

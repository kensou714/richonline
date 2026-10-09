#include "richonline_junction.hpp"
#include <bit>

namespace richnet {
RichonlineJunctionRequest decode_richonline_junction_request(View plain) {
    if (plain.size()!=6) throw CodecError("richonline_junction_request_size");
    if (read_le(plain.first(2))!=0x34) throw CodecError("richonline_junction_request_opcode");
    const auto direction=std::bit_cast<std::int8_t>(plain[4]);
    if (direction < -1 || direction > 3) throw CodecError("richonline_junction_direction_invalid");
    return {static_cast<std::uint16_t>(read_le(plain.subspan(2,2))),direction,plain[5]};
}
Bytes encode_richonline_junction_response(std::uint16_t game_server_id,std::int8_t direction) {
    if (direction < -1 || direction > 3) throw CodecError("richonline_junction_direction_invalid");
    Bytes response;
    append_le(response,0x4035,2);
    append_le(response,game_server_id,2);
    response.push_back(static_cast<std::uint8_t>(direction));
    return response;
}
bool RichonlineJunction::begin(const RichonlineRoadTopology& topology,
    const RichonlineJunctionEntry& entry,Clock::time_point now) {
    if (pending_) throw CodecError("richonline_junction_already_pending");
    if (entry.heading>3) throw CodecError("richonline_junction_heading_invalid");
    const auto& cell=topology.cell(entry.position);
    if (!cell.walkable) throw CodecError("richonline_junction_position_blocked");
    std::size_t degree=0;
    std::array<bool,4> permitted{};
    const auto reverse=(entry.heading+2U)%4U;
    for (std::size_t i=0;i<cell.neighbors.size();++i) {
        if (cell.neighbors[i]) ++degree;
        permitted[i]=cell.neighbors[i].has_value() && i!=reverse;
    }
    if (degree<=2) return false;
    // NEW608E sets pending22 and a6000ms UI timer. Server policy closes the
    // decision at that deadline even if the ordinary client only hides its UI.
    pending_=Pending{entry,permitted,now+std::chrono::milliseconds{6000}};
    return true;
}
RichonlineJunctionResult RichonlineJunction::finish(std::int8_t direction) {
    if (!pending_) throw CodecError("richonline_junction_not_pending");
    const auto heading=direction==-1 ? pending_->entry.heading : static_cast<std::uint8_t>(direction);
    auto response=encode_richonline_junction_response(game_id_,direction);
    pending_.reset();
    return {std::move(response),heading};
}
RichonlineJunctionResult RichonlineJunction::decide(View plain,Clock::time_point now) {
    const auto request=decode_richonline_junction_request(plain);
    if (!pending_) throw CodecError("richonline_junction_not_pending");
    if (request.calendar_counter!=pending_->entry.calendar_counter)
        throw CodecError("richonline_junction_counter_mismatch");
    if (now>=pending_->deadline) return finish(-1);
    // A stale/invalid UI choice resolves as the client's supported cancel,
    // preserving heading and closing this wait without disconnecting the game.
    if (request.direction!=-1 && !pending_->permitted[static_cast<std::size_t>(request.direction)])
        return finish(-1);
    return finish(request.direction);
}
std::optional<RichonlineJunctionResult> RichonlineJunction::poll(Clock::time_point now) {
    if (!pending_ || now<pending_->deadline) return {};
    return finish(-1);
}
}

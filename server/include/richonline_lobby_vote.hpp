#pragma once

#include "richonline_room_protocol.hpp"

#include <chrono>
#include <map>
#include <optional>
#include <vector>

namespace richnet {

enum class RichonlineVoteChoice : std::uint32_t { agree=0, oppose=1, abstain=2 };
struct RichonlineVoteProposal {
    Frame inner;
    std::uint32_t room;
    std::optional<std::uint32_t> kick_proposer;
    std::optional<std::uint32_t> kick_target;
    std::optional<RichonlineRoomDescription> map_description;
};
struct RichonlineVoteReply {
    std::uint32_t proposer;
    std::uint32_t inner_type;
    RichonlineVoteChoice choice;
};
RichonlineVoteProposal decode_richonline_vote39(const Frame& frame);
RichonlineVoteReply decode_richonline_vote40(const Frame& frame);
Frame encode_richonline_vote_prompt74(std::uint32_t proposer,const RichonlineVoteProposal& proposal);
Frame encode_richonline_vote_started75(std::uint32_t inner_type);
Frame encode_richonline_vote_result80(std::uint32_t proposer,std::uint32_t agree,
    std::uint32_t oppose,std::uint32_t abstain);

// A connection ID is a session generation, never an actor ID or socket handle.
struct RichonlineVoteMember {
    std::uint64_t connection;
    std::uint32_t actor;
    bool operator==(const RichonlineVoteMember&) const = default;
};
struct RichonlineVoteScope {
    std::uint32_t channel;
    std::uint32_t room;
    std::uint32_t owner;
    std::vector<RichonlineVoteMember> participants;
    bool game_pending = false;
};
enum class RichonlineVoteEnd { complete, timeout, room_changed };
struct RichonlineVoteResolution {
    RichonlineVoteScope scope;
    std::uint64_t proposer_connection;
    std::uint32_t proposer;
    RichonlineVoteProposal proposal;
    std::uint32_t agree,oppose,abstain;
    RichonlineVoteEnd reason;
    bool approved() const noexcept { return reason!=RichonlineVoteEnd::room_changed && agree>oppose; }
};

// One instance per channel/room. The caller serializes access and validates map
// resources before beginning; only an approved resolution may apply the action.
class RichonlineLobbyVote final {
public:
    using Clock=std::chrono::steady_clock;
    using Time=Clock::time_point;
    static constexpr auto duration=std::chrono::seconds(10);
    std::optional<RichonlineVoteResolution> begin(const RichonlineVoteScope& scope,
        std::uint64_t proposer_connection,const RichonlineVoteProposal& proposal,Time now);
    std::optional<RichonlineVoteResolution> reply(const RichonlineVoteScope& scope,
        std::uint64_t connection,const RichonlineVoteReply& reply,Time now);
    std::optional<RichonlineVoteResolution> poll(const RichonlineVoteScope& scope,Time now);
    std::optional<RichonlineVoteResolution> cancel();
    bool active() const noexcept { return active_.has_value(); }
    std::vector<RichonlineVoteMember> electorate() const;
private:
    struct Active {
        RichonlineVoteScope scope;
        std::uint64_t proposer_connection;
        std::uint32_t proposer;
        RichonlineVoteProposal proposal;
        Time deadline;
        std::map<std::uint64_t,RichonlineVoteChoice> replies;
    };
    RichonlineVoteResolution finish(RichonlineVoteEnd reason);
    std::optional<Active> active_;
};
} // namespace richnet

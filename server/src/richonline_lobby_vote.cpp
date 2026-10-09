#include "richonline_lobby_vote.hpp"

#include <algorithm>
#include <set>

namespace richnet {
namespace {
void inner_type(std::uint32_t type) {
    if(type!=23 && type!=27) throw CodecError("richonline_vote_inner_type");
}
void validate_scope(const RichonlineVoteScope& scope) {
    std::set<std::uint64_t> connections;
    std::set<std::uint32_t> actors;
    for(const auto& member:scope.participants) {
        if(!connections.insert(member.connection).second || !actors.insert(member.actor).second)
            throw CodecError("richonline_vote_duplicate_member");
    }
    if(!actors.contains(scope.owner)) throw CodecError("richonline_vote_owner_not_member");
}
bool same_scope(const RichonlineVoteScope& left,const RichonlineVoteScope& right) {
    if(left.channel!=right.channel || left.room!=right.room || left.owner!=right.owner || right.game_pending ||
       left.participants.size()!=right.participants.size()) return false;
    return std::is_permutation(left.participants.begin(),left.participants.end(),right.participants.begin());
}
}

RichonlineVoteProposal decode_richonline_vote39(const Frame& frame) {
    if(frame.wire_type!=39 || frame.payload.size()<16 || frame.payload.size()>max_frame_total-12)
        throw CodecError("richonline_vote39_shape");
    const View bytes=frame.payload;
    const auto length=read_le(bytes.first(4));
    if(length!=bytes.size()-8 || read_le(bytes.subspan(4,4))!=0 || read_le(bytes.subspan(12,4))!=length)
        throw CodecError("richonline_vote39_nested_header");
    const auto type=read_le(bytes.subspan(8,4));
    inner_type(type);
    RichonlineVoteProposal result{{type,Bytes(bytes.begin()+16,bytes.end())},0,{},{},{}};
    if(type==23) {
        const auto edit=decode_richonline_room_edit(result.inner.payload);
        result.room=edit.tag;
        result.map_description=edit.description;
    } else {
        if(result.inner.payload.size()!=44) throw CodecError("richonline_vote39_kick_size");
        const View kick=result.inner.payload;
        result.kick_proposer=read_le(kick.first(4));
        result.room=read_le(kick.subspan(4,4));
        result.kick_target=read_le(kick.subspan(8,4));
        if(std::find(kick.begin()+12,kick.end(),std::uint8_t{0})==kick.end())
            throw CodecError("richonline_vote39_reason_unterminated");
    }
    return result;
}
RichonlineVoteReply decode_richonline_vote40(const Frame& frame) {
    if(frame.wire_type!=40 || frame.payload.size()!=12) throw CodecError("richonline_vote40_shape");
    const View bytes=frame.payload;
    const auto type=read_le(bytes.subspan(4,4)),choice=read_le(bytes.subspan(8,4));
    inner_type(type);
    if(choice>2) throw CodecError("richonline_vote40_choice");
    return {read_le(bytes.first(4)),type,static_cast<RichonlineVoteChoice>(choice)};
}
Frame encode_richonline_vote_prompt74(std::uint32_t proposer,const RichonlineVoteProposal& proposal) {
    inner_type(proposal.inner.wire_type);
    Bytes bytes;
    const auto length=static_cast<std::uint32_t>(proposal.inner.payload.size()+8);
    // The middle header is the client's wrapper copied with its proven literal
    // marker; its otherwise ignored fields are not invented zero placeholders.
    for(const auto field:{proposer,proposal.inner.wire_type,length,0U,proposal.inner.wire_type,length})
        append_le(bytes,field,4);
    bytes.insert(bytes.end(),proposal.inner.payload.begin(),proposal.inner.payload.end());
    return {74,std::move(bytes)};
}
Frame encode_richonline_vote_started75(std::uint32_t type) {
    inner_type(type);Bytes bytes;append_le(bytes,type,4);return {75,std::move(bytes)};
}
Frame encode_richonline_vote_result80(std::uint32_t proposer,std::uint32_t agree,
    std::uint32_t oppose,std::uint32_t abstain) {
    Bytes bytes;for(const auto field:{proposer,agree,oppose,abstain})append_le(bytes,field,4);
    return {80,std::move(bytes)};
}

std::optional<RichonlineVoteResolution> RichonlineLobbyVote::begin(const RichonlineVoteScope& scope,
    std::uint64_t connection,const RichonlineVoteProposal& proposal,Time now) {
    if(active_) throw CodecError("richonline_vote_already_active");
    validate_scope(scope);
    if(scope.game_pending) throw CodecError("richonline_vote_during_game");
    if(proposal.room!=scope.room) throw CodecError("richonline_vote_room_mismatch");
    inner_type(proposal.inner.wire_type);
    const auto proposer=std::find_if(scope.participants.begin(),scope.participants.end(),
        [connection](const auto& member){return member.connection==connection;});
    if(proposer==scope.participants.end()) throw CodecError("richonline_vote_proposer_not_member");
    if(proposal.inner.wire_type==27) {
        if(!proposal.kick_target || proposal.kick_proposer!=proposer->actor)
            throw CodecError("richonline_vote_proposer_mismatch");
        if(*proposal.kick_target==proposer->actor) throw CodecError("richonline_vote_kick_self");
        if(std::none_of(scope.participants.begin(),scope.participants.end(),[&](const auto& member){
            return member.actor==*proposal.kick_target;})) throw CodecError("richonline_vote_target_not_member");
    } else if(!proposal.map_description) throw CodecError("richonline_vote_missing_map_description");
    active_=Active{scope,connection,proposer->actor,proposal,now+duration,{}};
    // Submitting the proposal is the initiator's agreement; the initiator gets
    // S2C75 instead of a redundant vote dialog. Every other participant votes.
    active_->replies.emplace(connection,RichonlineVoteChoice::agree);
    if(scope.participants.size()==1) return finish(RichonlineVoteEnd::complete);
    return {};
}
std::optional<RichonlineVoteResolution> RichonlineLobbyVote::reply(const RichonlineVoteScope& scope,
    std::uint64_t connection,const RichonlineVoteReply& reply,Time now) {
    if(!active_) throw CodecError("richonline_vote_not_active");
    // Reject cross-room and outsider replies without allowing them to cancel a
    // different room's vote. The owner calls poll when its own room changes.
    if(scope.channel!=active_->scope.channel || scope.room!=active_->scope.room)
        throw CodecError("richonline_vote_reply_scope_mismatch");
    if(std::none_of(active_->scope.participants.begin(),active_->scope.participants.end(),
       [connection](const auto& member){return member.connection==connection;}))
        throw CodecError("richonline_vote_voter_not_member");
    if(reply.proposer!=active_->proposer || reply.inner_type!=active_->proposal.inner.wire_type)
        throw CodecError("richonline_vote_reply_proposal_mismatch");
    if(static_cast<std::uint32_t>(reply.choice)>2) throw CodecError("richonline_vote40_choice");
    if(auto result=poll(scope,now)) return result;
    if(!active_->replies.emplace(connection,reply.choice).second)
        throw CodecError("richonline_vote_duplicate_reply");
    if(active_->replies.size()==active_->scope.participants.size()) return finish(RichonlineVoteEnd::complete);
    return {};
}
std::optional<RichonlineVoteResolution> RichonlineLobbyVote::poll(const RichonlineVoteScope& scope,Time now) {
    if(!active_) return {};
    if(!same_scope(active_->scope,scope)) return finish(RichonlineVoteEnd::room_changed);
    if(now>=active_->deadline) return finish(RichonlineVoteEnd::timeout);
    return {};
}
std::optional<RichonlineVoteResolution> RichonlineLobbyVote::cancel() {
    if(!active_) return {};
    return finish(RichonlineVoteEnd::room_changed);
}
std::vector<RichonlineVoteMember> RichonlineLobbyVote::electorate() const {
    std::vector<RichonlineVoteMember> result;
    if(active_) for(const auto& peer:active_->scope.participants)
        if(peer.connection!=active_->proposer_connection) result.push_back(peer);
    return result;
}
RichonlineVoteResolution RichonlineLobbyVote::finish(RichonlineVoteEnd reason) {
    RichonlineVoteResolution result{active_->scope,active_->proposer_connection,active_->proposer,
        active_->proposal,0,0,0,reason};
    // S2C80 has no cancellation flag. Invalidating the electorate voids all
    // ballots, so the client cannot display a majority for an unapplied action.
    if(reason==RichonlineVoteEnd::room_changed) {
        result.abstain=static_cast<std::uint32_t>(active_->scope.participants.size());
        active_.reset();
        return result;
    }
    for(const auto& peer:active_->scope.participants) {
        const auto it=active_->replies.find(peer.connection);
        const auto choice=it==active_->replies.end()?RichonlineVoteChoice::abstain:it->second;
        switch(choice) {
        case RichonlineVoteChoice::agree: ++result.agree;break;
        case RichonlineVoteChoice::oppose: ++result.oppose;break;
        case RichonlineVoteChoice::abstain: ++result.abstain;break;
        }
    }
    active_.reset();
    return result;
}
} // namespace richnet

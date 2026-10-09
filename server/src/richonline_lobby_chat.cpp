#include "richonline_lobby_chat.hpp"

#include <algorithm>
#include <string_view>

namespace richnet {
namespace {
// A service limit, not an inferred native array size. Includes the two display
// digits and trailing NUL; native 8B9F50 itself has no text length bound.
constexpr std::size_t max_chat_text = 400;
}

RichonlineChatResult richonline_lobby_chat(std::uint64_t connection,
    const Frame& request, std::span<const RichonlineChatPeer> peers) {
    const auto reject=[](const char* reason) { return RichonlineChatResult{{},reason}; };
    if (request.wire_type != 15) throw CodecError("richonline_chat_wire_invalid");
    const View payload(request.payload);
    if (payload.size()<28) return reject("chat_header_truncated");
    const auto word=[&](std::size_t offset) { return read_le(payload.subspan(offset,4)); };
    const auto length=word(20), scope=word(16), target=word(12);
    if (length<4 || length>max_chat_text || payload.size()!=28U+length)
        return reject("chat_text_length_invalid");
    const auto text=payload.subspan(28);
    if (text.back()!=0 || std::find(text.begin(),text.end()-1,0)!=text.end()-1)
        return reject("chat_text_termination_invalid");
    if (word(0)!=2 || word(4)!=2 || word(24)!=0)
        return reject("chat_address_class_or_reserved_invalid");
    const auto sender=std::find_if(peers.begin(),peers.end(),[&](const auto& peer) {return peer.connection==connection;});
    if (sender==peers.end()) return reject("chat_channel_admission_required");
    if (word(8)!=sender->actor) return reject("chat_sender_identity_mismatch");
    if (scope!=0 && scope!=1 && scope!=4) return reject("chat_scope_not_supported");
    const auto display=scope==4 ? '2' : static_cast<char>('0'+scope);
    if (text[0]!=display || text[1]<'0' || text[1]>'9')
        return reject("chat_display_prefix_invalid");
    // 87FD30 parses the first byte-wise bracket pair before ordinary chat.
    // Even an unknown bracket command is swallowed rather than displayed.
    const std::string_view body(reinterpret_cast<const char*>(text.data()),text.size()-1);
    const auto left=body.find('['),right=body.find(']');
    if (left!=std::string_view::npos && right!=std::string_view::npos && left+1<right)
        return reject("chat_control_tag_not_allowed");
    // Preserve CP950 bytes. Check structural pairs without converting or logging
    // private text; a Big5 trailing byte can itself be an ASCII bracket.
    for (std::size_t i=2;i+1<text.size();++i) {
        const auto byte=text[i];
        if (byte>=0x81 && byte<=0xfe) {
            if (++i+1>=text.size()) return reject("chat_big5_truncated");
            const auto trail=text[i];
            if (!((trail>=0x40 && trail<=0x7e)||(trail>=0xa1 && trail<=0xfe)))
                return reject("chat_big5_trail_invalid");
        } else if (byte<0x20 || byte>0x7e) return reject("chat_text_byte_invalid");
    }
    if (scope==0 && target!=sender->channel) return reject("chat_channel_target_mismatch");
    if (scope==1 && (!sender->room || target!=*sender->room))
        return reject("chat_room_membership_required");
    if (scope==4 && std::none_of(peers.begin(),peers.end(),[&](const auto& peer) {
        return peer.channel==sender->channel && peer.actor==target;
    })) return reject("chat_private_target_unavailable");
    RichonlineChatResult result;
    for (const auto& peer:peers) {
        if (peer.channel!=sender->channel) continue;
        const bool selected=scope==0 || (scope==1 && peer.room==sender->room) ||
            (scope==4 && (peer.actor==sender->actor || peer.actor==target));
        if (selected) result.deliveries.push_back({peer.connection,request});
    }
    return result;
}
}

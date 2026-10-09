#include "richonline_mail_service.hpp"
#include "richonline_lobby_error.hpp"

namespace richnet {
namespace {
std::string status_text(RichonlineMailMutation status){
    switch(status){
    case RichonlineMailMutation::changed:return "changed";
    case RichonlineMailMutation::duplicate:return "duplicate";
    case RichonlineMailMutation::missing:return "missing";
    case RichonlineMailMutation::token_mismatch:return "token_mismatch";
    case RichonlineMailMutation::attachment_pending:return "attachment_pending";
    case RichonlineMailMutation::inventory_conflict:return "inventory_conflict";
    case RichonlineMailMutation::attachment_expired:return "attachment_expired";
    case RichonlineMailMutation::no_attachment:return "no_attachment";
    case RichonlineMailMutation::attachment_unresolved:return "attachment_unresolved";
    }
    throw CodecError("richonline_mail_status_invalid");
}
}
std::vector<Frame> richonline_mail_snapshot(Storage& storage,const std::string& username,std::int64_t role){
    std::vector<Frame> frames;for(const auto& record:storage.mailbox(username,role))frames.push_back(encode_richonline_mail_record88(record));return frames;
}
RichonlineMailSendServiceReply richonline_mail_send_request(Storage& storage,const std::string& username,
    std::int64_t role,const Frame& request,std::int64_t now,const std::string& operation,
    RichonlineMailResultPolicy results,RichonlineMailMetadataPolicy metadata){
    if(request.wire_type!=46 || results.completed==results.refused)throw CodecError("richonline_mail_send_service_argument");
    RichonlineMailSendServiceReply reply;reply.frames.reserve(2);
    auto completion=richonline_lobby_failure(46,results.refused);
    try{
        const auto send=decode_richonline_mail_send46(request.payload);validate_richonline_mail_send46(send);
        auto sent=encode_richonline_mail_sent92(send.attachment_token);
        const auto delivered=storage.send_mail(username,role,send,now,operation,metadata);
        const auto code=static_cast<std::uint32_t>(results.completed);
        for(std::size_t i=0;i<4;++i)completion.payload[4+i]=static_cast<std::uint8_t>(code>>(8*i));
        reply.frames.push_back(std::move(completion));reply.frames.push_back(std::move(sent));
        reply.diagnostic=status_text(delivered.status);
        // A repeated operation clears the sender's pending UI, but never inserts
        // a second row in the recipient's live mail list.
        if(delivered.status==RichonlineMailMutation::changed)
            reply.recipient=RichonlineMailRecipientNotification{delivered.recipient_username,delivered.recipient_role,encode_richonline_mail_record88(delivered.record)};
        return reply;
    }catch(const StorageError& error){
        reply.frames.clear();reply.frames.push_back(std::move(completion));reply.diagnostic=error.what();return reply;
    }catch(const CodecError& error){
        reply.frames.clear();reply.frames.push_back(std::move(completion));reply.diagnostic=error.what();return reply;
    }
}
std::optional<RichonlineMailServiceReply> richonline_mail_request(Storage& storage,const std::string& username,
    std::int64_t role,const Frame& request,std::int64_t now,RichonlineMailResultPolicy policy){
    if(request.wire_type!=48 && request.wire_type!=49 && request.wire_type!=56)return {};
    if(policy.completed==policy.refused)throw CodecError("richonline_mail_result_policy_invalid");
    RichonlineMailServiceReply reply;reply.frames.reserve(2);
    // Construct generic reply storage before DB mutation, then only overwrite
    // its four-byte result. Payload text is a real empty NUL, not a filler area.
    auto completion=richonline_lobby_failure(request.wire_type,policy.refused);
    const auto complete=[&](RichonlineMailMutation status){
        const auto good=status==RichonlineMailMutation::changed || status==RichonlineMailMutation::duplicate;
        const auto code=static_cast<std::uint32_t>(good?policy.completed:policy.refused);
        for(std::size_t i=0;i<4;++i)completion.payload[4+i]=static_cast<std::uint8_t>(code>>(8*i));
        reply.frames.push_back(std::move(completion));reply.diagnostic=status_text(status);
    };
    try{
        if(request.wire_type==56){
            const auto read=decode_richonline_mail_read56(request.payload);
            reply.diagnostic=status_text(storage.read_mail(username,role,read.key));return reply;
        }
        if(request.wire_type==49){
            const auto key=decode_richonline_mail_delete49(request.payload);auto notification=encode_richonline_mail_deleted91(key);
            const auto status=storage.delete_mail(username,role,key);complete(status);
            if(status==RichonlineMailMutation::changed)reply.frames.push_back(std::move(notification));return reply;
        }
        const auto claim=decode_richonline_mail_claim48(request.payload);
        // Allocate the frame before commit; the actual granted item comes from
        // trusted storage, never from the request token or an invented item.
        Frame notification{93,Bytes(12)};
        for(std::size_t i=0;i<4;++i){notification.payload[4+i]=static_cast<std::uint8_t>(claim.key.high>>(8*i));notification.payload[8+i]=static_cast<std::uint8_t>(claim.key.low>>(8*i));}
        const auto result=storage.claim_mail(username,role,claim,now);
        if(result.status==RichonlineMailMutation::changed && !result.granted_item)throw StorageError("mail_committed_grant_missing");
        complete(result.status);
        if(result.status==RichonlineMailMutation::changed){
            for(std::size_t i=0;i<4;++i)notification.payload[i]=static_cast<std::uint8_t>(*result.granted_item>>(8*i));
            reply.frames.push_back(std::move(notification));
        }
        return reply;
    }catch(const StorageError& error){
        reply.frames.clear();if(request.wire_type!=56)reply.frames.push_back(std::move(completion));reply.diagnostic=error.what();return reply;
    }
}
}

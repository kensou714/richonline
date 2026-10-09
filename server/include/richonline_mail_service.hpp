#pragma once
#include "storage.hpp"

namespace richnet {
// Compatibility result codes must be deliberately configured. NEW consumes
// both through the registered generic callback; original mail enum is unknown.
struct RichonlineMailResultPolicy { std::int32_t completed; std::int32_t refused; };
struct RichonlineMailServiceReply { std::vector<Frame> frames; std::string diagnostic; };
struct RichonlineMailRecipientNotification { std::string username; std::int64_t role_id; Frame frame; };
struct RichonlineMailSendServiceReply {
    std::vector<Frame> frames;
    std::optional<RichonlineMailRecipientNotification> recipient;
    std::string diagnostic;
};
RichonlineMailSendServiceReply richonline_mail_send_request(Storage& storage,const std::string& username,
    std::int64_t role_id,const Frame& request,std::int64_t unix_now,const std::string& operation_id,
    RichonlineMailResultPolicy results,RichonlineMailMetadataPolicy metadata);
std::optional<RichonlineMailServiceReply> richonline_mail_request(Storage& storage,const std::string& username,
    std::int64_t role_id,const Frame& request,std::int64_t unix_now,RichonlineMailResultPolicy policy);
// Insert before bootstrap completion30;88 already includes body/read state.
std::vector<Frame> richonline_mail_snapshot(Storage& storage,const std::string& username,std::int64_t role_id);
}

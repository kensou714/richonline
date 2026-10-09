#pragma once
#include "codec.hpp"

namespace richnet {
struct RichonlineMailKey {
    std::uint32_t high;
    std::uint32_t low;
    bool operator==(const RichonlineMailKey&) const = default;
};
// The request constructor copies uninitialized stack bytes too. Preserve them;
// only the four proven fields may be interpreted, never treat them as identities.
struct RichonlineMailSend46 {
    std::array<std::uint8_t,348> original;
    Bytes recipient;
    Bytes subject;
    std::uint32_t attachment_token;
    Bytes body;
};
struct RichonlineMailClaim48 { RichonlineMailKey key; std::uint32_t attachment_token; };
struct RichonlineMailRead56 { RichonlineMailKey key; };
struct RichonlineMailActor {
    std::uint32_t opaque_actor_word;
    std::array<std::uint8_t,32> name;
    std::int16_t opaque_actor_short;
    std::array<std::uint8_t,2> opaque_padding;
};
// Arrays include the NUL and any original trailing bytes. No default/filler
// values are supplied for unknown fields. Callers must provide a complete record.
struct RichonlineMailRecord88 {
    std::uint32_t opaque_kind;
    RichonlineMailActor sender;
    RichonlineMailActor recipient;
    std::array<std::uint8_t,21> subject;
    std::array<std::uint8_t,12> date_text;
    std::array<std::uint8_t,11> time_text;
    RichonlineMailKey key;
    std::uint32_t read_word; // receiver tests equality with 1, others are unread.
    std::uint32_t attachment_token;
    std::array<std::uint8_t,204> body;
};
RichonlineMailSend46 decode_richonline_mail_send46(View payload);
// Validates the known text regions against NEW's smaller UI buffers and CP950.
// Does not invent actor/kind/date metadata or authorize an attachment transfer.
void validate_richonline_mail_send46(const RichonlineMailSend46& request);
RichonlineMailClaim48 decode_richonline_mail_claim48(View payload);
RichonlineMailKey decode_richonline_mail_delete49(View payload);
RichonlineMailRead56 decode_richonline_mail_read56(View payload);
RichonlineMailRecord88 decode_richonline_mail_record88(View payload);
Frame encode_richonline_mail_record88(const RichonlineMailRecord88& record);
Frame encode_richonline_mail_deleted91(RichonlineMailKey key);
Frame encode_richonline_mail_sent92(std::uint32_t transferred_item);
Frame encode_richonline_mail_claimed93(RichonlineMailKey key,std::uint32_t encoded_item);

struct RichonlineMailDelivery {
    RichonlineMailRecord88 record;
    // Required for a claimable attachment. Validated server-side grant policy
    // chooses encoded_item and expiry; no client-supplied token grants an item.
    std::optional<std::uint32_t> granted_item;
    std::int64_t attachment_expires_at;
    std::string operation_id;
};
enum class RichonlineMailMutation { changed, duplicate, missing, token_mismatch, attachment_pending, inventory_conflict, attachment_expired, no_attachment, attachment_unresolved };
struct RichonlineMailClaimResult { RichonlineMailMutation status; std::optional<std::uint32_t> granted_item; };
// These actor integers/padding are copied by NEW but not interpreted by its mail
// UI. A server must choose its compatibility values explicitly; they are NOT
// recovered role IDs, levels, or flags. Names always come from authenticated DB roles.
struct RichonlineMailActorCompatibility {
    std::uint32_t opaque_word;
    std::int16_t opaque_short;
    std::array<std::uint8_t,2> opaque_padding;
};
struct RichonlineMailMetadataPolicy {
    RichonlineMailActorCompatibility sender;
    RichonlineMailActorCompatibility recipient;
};
struct RichonlineMailSendResult {
    RichonlineMailMutation status;
    std::string recipient_username;
    std::int64_t recipient_role;
    RichonlineMailRecord88 record;
};
}

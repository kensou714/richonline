#include "original_blacklist.hpp"
#include "blacklist_store.hpp"

#include <algorithm>

namespace richnet {
namespace {
View name(View slot) {
    const auto end = std::find(slot.begin(), slot.end(), std::uint8_t{0});
    const auto value = slot.first(static_cast<std::size_t>(end - slot.begin()));
    if (value.empty()) throw CodecError("black_name_empty");
    return value;
}
void record(Bytes& output, std::uint32_t type, View body) {
    output.push_back(13); output.push_back(10);
    append_le(output, type, 4);
    append_le(output, static_cast<std::uint32_t>(body.size()), 4);
    output.insert(output.end(), body.begin(), body.end());
}
}

Bytes original_blacklist_response(BlacklistStore& store, View request) {
    if (request.size() < 10 || request[0] != 13 || request[1] != 10)
        throw CodecError("black_invalid_magic");
    const auto type = read_le(request.subspan(2,4));
    if (type > 4) throw CodecError("black_type_unsupported");
    const auto length = read_le(request.subspan(6,4));
    const auto expected_length = type == 4 ? 97U : (type == 1 || type == 2 ? 96U : 64U);
    if (length != expected_length || request.size() != 10 + length)
        throw CodecError("black_invalid_payload_length");
    const auto role_name = name(request.subspan(10,32));
    const auto account_md5 = request.subspan(42,32);
    if (!std::all_of(account_md5.begin(), account_md5.end(), [](std::uint8_t c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    })) throw CodecError("black_digest_invalid");
    Bytes output;
    switch (type) {
    case 0:
        for (const auto& entry : store.list(role_name, account_md5)) {
            Bytes body(33,0);
            std::copy(entry.target.begin(), entry.target.end(), body.begin());
            body[32] = entry.enabled ? 1 : 0;
            record(output,0,body);
        }
        // Empty name ends the list. Remaining bytes are unused by the client.
        record(output,0,Bytes(33,0));
        return output;
    case 1:
    case 2: {
        const auto target = name(request.subspan(74,32));
        bool changed = true;
        if (type == 1) store.add(role_name,account_md5,target);
        else changed = store.remove(role_name,account_md5,target);
        Bytes body;
        // Original receiver treats zero as success; nonzero is failure.
        append_le(body,changed ? 0U : 1U,4);
        body.resize(36,0);
        if (changed) std::copy(target.begin(),target.end(),body.begin()+4);
        record(output,type,body);
        return output;
    }
    case 3:
        throw CodecError("black_mode3_semantics_unverified");
    case 4: {
        const auto enabled = request[106];
        if (enabled > 1) throw CodecError("black_enabled_flag_invalid");
        if (!store.set_enabled(role_name,account_md5,name(request.subspan(74,32)),enabled != 0))
            throw CodecError("black_flag_target_missing");
        return {};
    }
    }
    throw CodecError("black_type_unsupported");
}
}

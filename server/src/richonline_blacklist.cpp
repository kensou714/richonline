#include "richonline_blacklist.hpp"
#include "blacklist_store.hpp"

#include <algorithm>

namespace richnet {
namespace {
View name(View slot) {
    const auto end=std::find(slot.begin(),slot.end(),std::uint8_t{0});
    const auto result=slot.first(static_cast<std::size_t>(end-slot.begin()));
    if(result.empty()) throw CodecError("richonline_black_name_empty");
    return result;
}
void record(Bytes& output,std::uint32_t type,View payload) {
    output.insert(output.end(),{13,10});
    append_le(output,type,4);
    append_le(output,static_cast<std::uint32_t>(payload.size()),4);
    output.insert(output.end(),payload.begin(),payload.end());
}
}

Bytes richonline_blacklist_response(BlacklistStore& store,View request) {
    if(request.size()<10 || request[0]!=13 || request[1]!=10)
        throw CodecError("richonline_black_invalid_magic");
    const auto type=read_le(request.subspan(2,4));
    if(type>4) throw CodecError("richonline_black_type_unsupported");
    const auto length=read_le(request.subspan(6,4));
    const auto expected=type==4 ? 97U : (type==1 || type==2 ? 96U : 64U);
    if(length!=expected || request.size()!=10+length)
        throw CodecError("richonline_black_invalid_payload_length");
    const auto owner=name(request.subspan(10,32));
    const auto digest=request.subspan(42,32);
    if(!std::all_of(digest.begin(),digest.end(),[](std::uint8_t value){
        return (value>='0' && value<='9') || (value>='a' && value<='f');
    })) throw CodecError("richonline_black_digest_invalid");
    Bytes output;
    switch(type) {
    case 0:
        for(const auto& entry:store.list(owner,digest)) {
            // 858FB0 consumes name32 and flag1; flag is UI/cache enabled state.
            Bytes payload(33,0); // Fixed C-string padding; not business values.
            std::copy(entry.target.begin(),entry.target.end(),payload.begin());
            payload[32]=entry.enabled ? 1 : 0;
            record(output,0,payload);
        }
        // Empty name terminates; the receiver never reads this record's flag.
        record(output,0,Bytes(33,0));
        break;
    case 1:
    case 2: {
        const auto target=name(request.subspan(74,32));
        bool success=true;
        if(type==1) {
            // A successful NEW add always sets cached enabled=1 (858FB0).
            store.add_enabled(owner,digest,target);
        } else success=store.remove(owner,digest,target);
        Bytes payload;
        // 6B1F60: 0=success, 1=capacity, all other nonzero=generic failure.
        // 6B2040 refreshes only on 0; failed removal leaves the client cache intact.
        append_le(payload,success ? 0U : 2U,4);
        payload.resize(36,0);
        std::copy(target.begin(),target.end(),payload.begin()+4);
        record(output,type,payload);
        break;
    }
    case 3: {
        // Builder exists but has no caller; its callback 6B2080 ignores status.
        // Explicit unsupported outcome. No invented clear/reset mutation.
        Bytes payload;
        append_le(payload,0xffffffffU,4);
        record(output,3,payload);
        break;
    }
    case 4: {
        const auto enabled=request[106];
        if(enabled>1) throw CodecError("richonline_black_enabled_invalid");
        if(!store.set_enabled(owner,digest,name(request.subspan(74,32)),enabled!=0))
            throw CodecError("richonline_black_target_missing");
        // 85AD70 changes its cache immediately; 858FB0 rejects response type4.
        break;
    }
    }
    return output;
}
}

#include "richonline_mall.hpp"
#include <bit>
#include <cmath>

namespace richnet {
RichonlineMallActivate63 decode_richonline_mall_activate63(View payload) {
    if(payload.size()!=8)throw CodecError("mall_activate63_size_invalid");
    const auto mode=read_le(payload.first(4));
    if(mode!=1&&mode!=2)throw CodecError("mall_activation_currency_invalid");
    const auto key=read_le(payload.subspan(4,4));
    if((key&4095U)==0)throw CodecError("mall_activation_product_missing");
    return {static_cast<RichonlineMallCurrency>(mode),key};
}
Frame encode_richonline_mall_activated213(const RichonlineMallActivated213& result) {
    const auto mode=static_cast<std::uint32_t>(result.currency);
    if(mode!=1&&mode!=2)throw CodecError("mall_activation_currency_invalid");
    if((result.old_key&4095U)==0||(result.old_key&4095U)!=(result.new_key&4095U)||
        (result.old_key&0x40000000U)==0||(result.new_key&0x40010000U)!=0||!std::isfinite(result.charge)||result.charge<=0)
        throw CodecError("mall_activation_result_invalid");
    Bytes payload;append_le(payload,result.old_key,4);append_le(payload,result.new_key,4);append_le(payload,mode,4);
    const auto bits=std::bit_cast<std::uint64_t>(result.charge);
    append_le(payload,static_cast<std::uint32_t>(bits),4);append_le(payload,static_cast<std::uint32_t>(bits>>32U),4);
    return {213,std::move(payload)};
}
RichonlineMallPurchase18 decode_richonline_mall_purchase18(View payload) {
    if(payload.size()!=16)throw CodecError("mall_purchase18_size_invalid");
    // 869170 writes a local head=0, one entry and quantity=1. The previous
    // C2S16 distinguishes purchase(-1) from an existing-item operation(-2).
    if(read_le(payload.first(4))!=0||read_le(payload.subspan(4,4))!=1||read_le(payload.subspan(12,4))!=1)
        throw CodecError("mall_purchase18_shape_invalid");
    return {read_le(payload.subspan(8,4))};
}
Frame encode_richonline_mall_added77(const RichonlineMallGrant& grant) {
    if(grant.owned_key==0||grant.evidence.empty()||grant.evidence.size()>1024||grant.evidence.find('\0')!=std::string::npos)
        throw CodecError("mall_grant_evidence_required");
    Bytes result;append_le(result,grant.opaque_word0,4);append_le(result,grant.owned_key,4);append_le(result,grant.opaque_word2,4);
    return {77,std::move(result)};
}
}

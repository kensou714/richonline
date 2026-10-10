#include "richonline_mall_service.hpp"
#include "richonline_lobby_error.hpp"
#include "lua_server.hpp"
#include <bit>
#include <limits>

namespace richnet {
RichonlineMallService::RichonlineMallService(const RichonlineMallCatalog& catalog,std::string prefix,
    RichonlineMallCompatibilityPolicy policy):catalog_(catalog),operation_prefix_(std::move(prefix)),policy_(std::move(policy)) {
    if(operation_prefix_.empty()||operation_prefix_.size()>220||operation_prefix_.find('\0')!=std::string::npos||
        policy_.evidence.empty()||policy_.evidence.size()>1024||policy_.evidence.find('\0')!=std::string::npos||policy_.refused>=0)
        throw CodecError("mall_service_policy_invalid");
    if((policy_.date_version==RichonlineInventoryDateVersion::original_2005&&!policy_.verified_client_compatibility_id.empty())||
       (policy_.date_version==RichonlineInventoryDateVersion::compat_2021_v1&&policy_.verified_client_compatibility_id!=richonline_inventory_compatibility_id))
        throw CodecError("mall_client_date_mode_mismatch");
    static_cast<void>(encode_richonline_inventory_date(13,{},policy_.date_version));
    script_=LuaServer::create();
}
std::optional<RichonlineMallServiceReply> RichonlineMallService::request(Storage& storage,const std::string& username,
    std::int64_t role,const Frame& frame,std::int64_t now) {
    if(frame.wire_type!=16&&frame.wire_type!=18&&frame.wire_type!=63)return {};
    storage.require_inventory_date_version(policy_.date_version);
    if(frame.wire_type==16) {
        operation_=0;
        if(frame.payload.size()!=4)throw CodecError("mall_selection16_size_invalid");
        const auto mode=std::bit_cast<std::int32_t>(read_le(frame.payload));
        if(mode!=-1&&mode!=-2)throw CodecError("mall_selection16_mode_invalid");
        operation_=mode;return RichonlineMallServiceReply{{},mode==-1?"purchase_selected":"existing_item_selected",{}};
    }
    RichonlineMallServiceReply reply;reply.frames.reserve(1);
    auto refused=richonline_lobby_failure(frame.wire_type,policy_.refused);
    const auto reject=[&](const std::string& reason) {
        reply.frames.push_back(std::move(refused));reply.diagnostic=reason;return reply;
    };
    if(frame.wire_type==63) {
        const auto request=decode_richonline_mall_activate63(frame.payload);
        Frame notification{213,Bytes(20)}; //allocate before any DB commit
        try {
            if(sequence_==std::numeric_limits<std::uint64_t>::max())throw CodecError("mall_operation_sequence_exhausted");
            auto result=storage.activate_mall_item(username,role,catalog_,request,now,policy_.date_version,
                operation_prefix_+":"+std::to_string(++sequence_),policy_.evidence);
            switch(result.status) {
            case RichonlineMallActivationStatus::activated: {
                if(!result.activated)throw CodecError("mall_activation_result_missing");
                const auto& actual=*result.activated;
                const auto bits=std::bit_cast<std::uint64_t>(actual.charge);
                const std::array<std::uint32_t,5> words{actual.old_key,actual.new_key,static_cast<std::uint32_t>(actual.currency),static_cast<std::uint32_t>(bits),static_cast<std::uint32_t>(bits>>32U)};
                for(std::size_t index=0;index<words.size();++index)for(std::size_t byte=0;byte<4;++byte)
                    notification.payload[index*4+byte]=static_cast<std::uint8_t>(words[index]>>(8*byte));
                reply.frames.push_back(std::move(notification));reply.role_refresh=std::move(result.role);reply.role_refresh_after_frames=true;reply.diagnostic="activated";return reply;
            }
            case RichonlineMallActivationStatus::replayed:return reject("mall_session_operation_reused");
            case RichonlineMallActivationStatus::insufficient_funds:return reject("mall_insufficient_funds");
            case RichonlineMallActivationStatus::inventory_conflict:return reject("mall_inventory_conflict");
            case RichonlineMallActivationStatus::missing:return reject("mall_activation_item_missing");
            case RichonlineMallActivationStatus::expired:return reject("mall_activation_item_expired");
            }
            throw CodecError("mall_activation_status_invalid");
        }catch(const StorageError& error){return reject(error.what());}
         catch(const CodecError& error){return reject(error.what());}
    }
    const auto selected=operation_;operation_=0;
    const auto request=decode_richonline_mall_purchase18(frame.payload);
    if(selected==0)return reject("mall_purchase_without_selection");
    if(selected==-2)return reject("mall_existing_item_sale_rule_unproven");
    try {
        const auto& product=catalog_.purchasable(request.encoded_item);
        const auto mode=(request.encoded_item>>12U)&15U;
        const auto& term=product.term.at(mode-1);
        const bool timed=term.years!=0||term.months!=0||term.days!=0;
        std::int64_t expiry=0;
        if(script_) {
            // Lua 规划商品资格和期限，核心日历函数保持月底裁剪及 UTC 时间语义。
            // 此阶段没有数据库副作用；脚本失败只能拒绝本次购买，不能先扣钱。
            LuaValue plan;
            try {
                plan=script_->call("mall.purchase_policy",{{"product",product.id},{"currency",mode},
                    {"fold",product.fold},{"level",product.level},{"score",product.score},
                    {"price",product.price.at(mode-1)},{"type",product.type},{"subtype",product.subtype},
                    {"term",{{"years",term.years},{"months",term.months},{"days",term.days}}},
                    {"date_epoch",static_cast<std::uint16_t>(policy_.date_version)}},
                    {{"mall.calendar_expiry",[&](const LuaValue& args) {
                        const auto integer=[&](const char* key,std::uint32_t maximum) {
                            const auto& value=args.at(key);
                            if(!value.is_number_integer() || value<0 || value>maximum)
                                throw CodecError("lua_mall_term_invalid");
                            return value.get<std::uint32_t>();
                        };
                        const auto years=integer("years",100),months=integer("months",1200),days=integer("days",36600);
                        const auto expires=years || months || days ? richonline_inventory_calendar_expiry(now,years,months,days) : 0;
                        return LuaValue{{"expires_at",expires},{"year",expires ? richonline_inventory_utc_date(expires).year : 0}};
                    }}});
                if(!plan.at("allowed").get<bool>()) {
                    const auto reason=plan.at("reason").get<std::string>();
                    if(reason.empty() || reason.size()>256 || reason.find_first_of("\r\n")!=reason.npos)
                        throw CodecError("lua_mall_refusal_invalid");
                    return reject(reason);
                }
                const auto& value=plan.at("expires_at");
                if(!value.is_number_integer() || value<0 || value>253402300799LL)
                    throw CodecError("lua_mall_expiry_invalid");
                expiry=value.get<std::int64_t>();
                // 现有客户端按资源显示价格和期限；活动改变这些值前必须有配套协议。
                if(expiry!=(timed?richonline_inventory_calendar_expiry(now,term.years,term.months,term.days):0))
                    throw CodecError("lua_mall_expiry_resource_mismatch");
            } catch(const std::exception& error) {
                return reject(std::string("mall_script_policy_failed: ")+error.what());
            }
        } else {
            expiry=timed?richonline_inventory_calendar_expiry(now,term.years,term.months,term.days):0;
            if(product.fold!=1)return reject("mall_purchase_bundle_grant_unproven");
            if(product.level!=0)return reject("mall_purchase_level_rule_unproven");
        }
        if(sequence_==std::numeric_limits<std::uint64_t>::max())throw CodecError("mall_operation_sequence_exhausted");
        RichonlineMallPurchase purchase{operation_prefix_+":"+std::to_string(++sequence_),request,
            {richonline_inventory_key_from_expiry(request.encoded_item,expiry,policy_.date_version),expiry,
                policy_.ignored_word0,policy_.ignored_word2,policy_.evidence},policy_.date_version};
        auto notice=encode_richonline_mall_added77(purchase.grant); // allocate before commit
        auto result=storage.purchase_mall_item(username,role,catalog_,purchase,now);
        switch(result.status) {
        case RichonlineMallPurchaseStatus::purchased:
            reply.frames.push_back(std::move(notice));reply.role_refresh=std::move(result.role);reply.diagnostic=timed?"purchased_timed":"purchased_permanent";return reply;
        case RichonlineMallPurchaseStatus::replayed:
            // A wire77 replay would add a duplicate native object. The session
            // prefix/sequence must be unique; report reuse rather than duplicate.
            return reject("mall_session_operation_reused");
        case RichonlineMallPurchaseStatus::insufficient_funds:return reject("mall_insufficient_funds");
        case RichonlineMallPurchaseStatus::inventory_conflict:return reject("mall_inventory_conflict");
        case RichonlineMallPurchaseStatus::inventory_full:return reject("mall_inventory_full");
        }
        throw CodecError("mall_purchase_status_invalid");
    } catch(const StorageError& error){return reject(error.what());}
      catch(const CodecError& error){return reject(error.what());}
}
}

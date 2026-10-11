#include "richonline_boss_recovery.hpp"
#include "lua_server.hpp"
#include <algorithm>
#include <cmath>
#include <limits>

namespace richnet {
RichonlineBossRecoveryPlan plan_richonline_boss_recovery(const RichonlineNativeBossRecovery& rules,
    std::uint32_t cash_cap,std::uint32_t cash,const RichonlineActorStatus& status,LuaServer* script) {
    constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
    if(!rules.amount || rules.amount>maximum || !cash_cap || cash_cap>maximum || cash>maximum)
        throw CodecError("richonline_native_boss_restore_context_invalid");
    const bool frenzy=status.native_boss_frenzy.has_value();
    const auto factor=frenzy ? static_cast<double>((*status.native_boss_frenzy)[2]) : 1.0;
    if(!std::isfinite(factor) || factor<0.0)
        throw CodecError("richonline_native_boss_restore_factor_invalid");
    // 7FA3F0先将整数恢复值存为float，再用x87乘法和+0.5取整；不要额外将乘积存为float。
    const auto amount_float=static_cast<double>(static_cast<float>(rules.amount));
    RichonlineBossRecoveryPlan plan;
    if(status.boss_restore_eligible && cash<cash_cap) {
        auto amount=rules.amount;
        if(frenzy) {
            const auto scaled=amount_float*factor+0.5;
            if(!std::isfinite(scaled) || scaled>static_cast<double>(maximum))
                throw CodecError("richonline_native_boss_restore_overflow");
            amount=static_cast<std::uint32_t>(scaled);
        }
        plan={std::min(amount,cash_cap-cash),true};
    }
    if(script) {
        const auto result=script->call("boss.native_recovery",{{"amount",rules.amount},
            {"amount_float",amount_float},{"cash",cash},{"cap",cash_cap},
            {"eligible",status.boss_restore_eligible},{"frenzy",frenzy},{"factor",factor}});
        const LuaValue expected{{"amount",plan.amount},{"consume_eligibility",plan.consume_eligibility}};
        if(result!=expected || !result.at("amount").is_number_integer() ||
            !result.at("consume_eligibility").is_boolean())
            throw CodecError("lua_native_boss_recovery_invalid");
    }
    return plan;
}
}

#include "richonline_classic_interest.hpp"
#include "lua_server.hpp"

#include <limits>

namespace richnet {
std::vector<RichonlineGameFundsUpdate> prepare_richonline_classic_interest(
    std::span<const std::uint8_t> active,const RichonlineGameLedger& ledger,
    const std::shared_ptr<LuaServer>& script) {
    if(active.size()<2 || active.size()>4 || ledger.actor_count()!=active.size())
        throw CodecError("richonline_classic_interest_context_invalid");
    std::vector<RichonlineGameFundsUpdate> updates;
    updates.reserve(active.size());
    auto actors=LuaValue::array(),effects=LuaValue::array();
    constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
    for(std::uint8_t actor=0;actor<active.size();++actor) {
        if(active[actor]>1) throw CodecError("richonline_classic_interest_active_invalid");
        if(!active[actor]) continue;
        const auto before=ledger.snapshot(actor);
        if(!before.funds.deposit) throw CodecError("richonline_classic_interest_deposit_unknown");
        const auto deposit=*before.funds.deposit;
        // 67E8A0使用signed idiv 10；账本余额非负，因此整数除法即为原版取整。
        const auto interest=deposit/10U;
        if(deposit>maximum || interest>maximum-deposit)
            throw CodecError("richonline_classic_interest_deposit_overflow");
        auto after=before.funds;
        after.deposit=deposit+interest;
        actors.push_back({{"actor",actor},{"deposit",deposit}});
        effects.push_back({{"actor",actor},{"interest",interest},{"after_deposit",*after.deposit}});
        // 零利息也保留快照，提交时统一确认未被其他资金事务改变。
        updates.push_back({actor,before,after});
    }
    if(updates.empty()) throw CodecError("richonline_classic_interest_no_active_actor");
    if(script) {
        const auto plan=script->call("interest.classic",{{"actors",actors}});
        if(plan!=LuaValue{{"effects",effects}})
            throw CodecError("lua_classic_interest_plan_invalid");
        for(const auto& effect:plan.at("effects"))
            for(const auto* key:{"actor","interest","after_deposit"})
                if(!effect.at(key).is_number_integer())
                    throw CodecError("lua_classic_interest_plan_invalid");
    }
    return updates;
}
}

#pragma once
#include "richonline_mall_catalog.hpp"
#include "richonline_inventory_date.hpp"
#include <nlohmann/json.hpp>
#include <functional>

namespace richnet {
struct RichonlineMallPurchase18 { std::uint32_t encoded_item; };
struct RichonlineMallUse41 { std::uint32_t owned_key,target; };
RichonlineMallUse41 decode_richonline_mall_use41(View payload);
using RichonlineMallUsePrepare=std::function<void(const std::vector<std::uint32_t>&)>;
RichonlineMallPurchase18 decode_richonline_mall_purchase18(View payload);
struct RichonlineMallActivate63 { RichonlineMallCurrency currency; std::uint32_t owned_key; };
RichonlineMallActivate63 decode_richonline_mall_activate63(View payload);
struct RichonlineMallActivated213 {
    std::uint32_t old_key,new_key;
    RichonlineMallCurrency currency;
    double charge;
};
struct RichonlineMallEquipmentSlot { std::int64_t role; std::uint32_t slot; };
// 在激活事务持锁期间构造的投影，用于扣款前准备全部在线同步消息；回调不得再访问Storage。
struct RichonlineMallActivationPreview {
    RichonlineMallActivated213 activated;
    std::vector<std::uint32_t> inventory;
    std::vector<RichonlineMallEquipmentSlot> equipment;
};
using RichonlineMallActivationPrepare=std::function<void(const RichonlineMallActivationPreview&)>;
Frame encode_richonline_mall_activated213(const RichonlineMallActivated213& result);
// This adapter is trusted server configuration, never data supplied by a client.
// Opaque words are deliberately mandatory: NEW77 ignores them, but their producer
// meanings remain unproven. No default or implicit date/key policy is supplied.
struct RichonlineMallGrant {
    std::uint32_t owned_key;
    std::int64_t expires_at;
    std::uint32_t opaque_word0,opaque_word2;
    std::string evidence;
};
struct RichonlineMallBagAward {
    std::array<std::uint32_t,3> dice;
    RichonlineMallGrant grant;
};
// 在Storage事务持锁期间调用；仅准备消息，不能重入Storage或发送网络回复。
using RichonlineMallBagPrepare=std::function<void(const RichonlineMallBagAward&,const std::vector<std::uint32_t>&)>;
using RichonlineMallBagRoll=std::function<std::array<std::uint32_t,3>()>;
struct RichonlineMallPurchase {
    std::string operation_id;
    RichonlineMallPurchase18 request;
    RichonlineMallGrant grant;
    RichonlineInventoryDateVersion date_version=RichonlineInventoryDateVersion::original_2005;
};
enum class RichonlineMallPurchaseStatus { purchased,replayed,insufficient_funds,inventory_conflict,inventory_full };
struct RichonlineMallPurchaseResult {
    RichonlineMallPurchaseStatus status;
    std::optional<RichonlineMallGrant> granted;
    // Always current SQLite state, including on idempotent replay. A caller must
    // refresh balances from this row, not from a historical receipt snapshot.
    nlohmann::json role;
};
Frame encode_richonline_mall_added77(const RichonlineMallGrant& grant);
enum class RichonlineMallActivationStatus { activated,replayed,insufficient_funds,inventory_conflict,missing,expired };
struct RichonlineMallActivationResult {
    RichonlineMallActivationStatus status;
    std::optional<RichonlineMallActivated213> activated;
    nlohmann::json role;
};
}

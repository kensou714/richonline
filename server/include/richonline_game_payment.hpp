#pragma once
#include "codec.hpp"
#include "game_charge.hpp"
#include "richonline_game_ledger.hpp"
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <memory>

namespace richnet {
struct RichonlineGoldCharges {
    std::map<std::int32_t,std::int32_t> values;
    std::int32_t require(std::int32_t index) const;
};
RichonlineGoldCharges parse_richonline_gold_charges(View decoded);
RichonlineGoldCharges load_richonline_gold_charges(const std::filesystem::path& path);
std::uint32_t richonline_initial_reserve(double account_gold,double entry_fee,const RichonlineGoldCharges& charges);
enum class RichonlineDiceVehicle { walking, motorcycle, car };
struct RichonlinePaidDiceEquipment {
    bool equipped_die; // NEW actor +160 > 0: free controlled selection.
    bool vehicle_discount; // NEW actor +148 low-12 item, Prop record byte +115.
    RichonlineDiceVehicle dice_vehicle=RichonlineDiceVehicle::walking;
};
enum class RichonlinePaymentStatus { committed, duplicate, insufficient_reserve, account_refused, recovery_required };
struct RichonlinePaymentResult {
    RichonlinePaymentStatus status;
    std::int32_t charge;
    std::uint32_t reserve_after;
};

// Authenticated account binding belongs to the caller; debit executes synchronously.
// All paid actions for this actor must share this coordinator and ledger.
class RichonlineGamePayment {
public:
    using Debit = std::function<GameGoldChargeResult(const GameGoldCharge&)>;
    RichonlineGamePayment(std::shared_ptr<RichonlineGameLedger> ledger,std::uint8_t actor,RichonlineGoldCharges charges,Debit debit);
    RichonlinePaymentResult paid_die(const std::string& operation_id,std::uint8_t selected_die,RichonlinePaidDiceEquipment equipment);
    // Pure price lookup used to construct/validate the full movement response before charging.
    std::int32_t quote_paid_die(std::uint8_t selected_die,RichonlinePaidDiceEquipment equipment) const;
    std::int32_t quote_random_dice(std::uint8_t count,RichonlinePaidDiceEquipment equipment) const;
    RichonlinePaymentResult random_dice(const std::string& operation_id,std::uint8_t count,
        RichonlinePaidDiceEquipment equipment);
    RichonlinePaymentResult shop_refresh(const std::string& operation_id);
    std::uint32_t reserve() const;
private:
    RichonlinePaymentResult pay(const std::string& operation,std::string reason,std::int32_t cost);
    struct Completed { std::string reason; std::int32_t cost; RichonlinePaymentResult result; };
    std::shared_ptr<RichonlineGameLedger> ledger_;
    std::uint8_t actor_;
    RichonlineGoldCharges charges_;
    Debit debit_;
    mutable std::mutex mutex_;
    std::map<std::string,Completed> completed_;
};
}

#pragma once
#include "original_card_resources.hpp"
#include "original_map.hpp"
#include "original_shop_wire.hpp"
#include <chrono>
#include <functional>
#include <memory>

namespace richnet {
using OriginalShopClock = std::chrono::steady_clock;
struct OriginalShopCatalog {
    std::vector<std::int16_t> offers, combination_outputs;
    std::map<std::int16_t,std::int32_t> prices;
    std::map<std::int16_t,std::int16_t> counts;
};
OriginalShopCatalog original_shop_catalog(const OriginalPropCards& props, const OriginalMapResources& map);
struct OriginalShopWallet {
    OriginalInventory inventory;
    std::uint32_t tickets;
    std::uint32_t account_reserve;
};
struct OriginalShopSetup {
    std::uint16_t instance, context;
    std::uint8_t owner;
    OriginalShopClock::time_point opened;
    std::optional<std::uint32_t> refresh_gold_cost;
};
struct OriginalShopResult {
    std::vector<Bytes> messages;
    bool closed = false;
    std::optional<std::string> rejection;
    std::uint32_t account_charge = 0;
};
class OriginalShop final {
public:
    OriginalShop(OriginalShopSetup setup, OriginalShopCatalog catalog,
        std::shared_ptr<const OriginalCardCombinations> combinations, OriginalShopWallet wallet,
        std::function<std::uint32_t(std::uint32_t)> random);
    const OriginalShopWallet& wallet() const noexcept { return wallet_; }
    bool closed() const noexcept { return closed_; }
    std::uint16_t context() const noexcept { return setup_.context; }
    OriginalShopClock::time_point deadline() const noexcept { return setup_.opened+std::chrono::seconds(10); }
    Bytes open_message() const;
    OriginalShopResult handle(const OriginalShopRequest& request, OriginalShopClock::time_point now);
    OriginalShopResult poll(OriginalShopClock::time_point now);
private:
    OriginalShopSetup setup_;
    OriginalShopCatalog catalog_;
    std::shared_ptr<const OriginalCardCombinations> combinations_;
    OriginalShopWallet wallet_;
    std::function<std::uint32_t(std::uint32_t)> random_;
    std::array<OriginalCardSlot,12> stock_;
    bool closed_ = false;
    unsigned refreshes_ = 0;
    std::array<OriginalCardSlot,12> select_stock() const;
    OriginalShopResult close(std::optional<std::string> reason = {});
    OriginalShopResult buy(std::int8_t index);
    OriginalShopResult sell(std::int8_t slot);
    OriginalShopResult refresh();
};
}

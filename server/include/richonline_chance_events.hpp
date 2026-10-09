#pragma once
#include "richonline_chance.hpp"

namespace richnet {
// These resource columns are preserved, not interpreted as recovered probabilities.
struct RichonlineChanceEvent {
    std::int16_t id;
    std::uint8_t category;
    std::array<std::int32_t,3> raw_weights;
    std::array<std::int32_t,2> raw_parameters;
    std::string candidates, image, text;
};
class RichonlineChanceEventTable {
public:
    static RichonlineChanceEventTable parse(std::string_view news,
        std::string_view props = {}, std::string_view strings = {});
    static RichonlineChanceEventTable load(const std::filesystem::path& root);
    const RichonlineChanceEvent& event(std::string_view map, std::int32_t id) const;
    std::size_t size(std::string_view map) const;
    std::string_view card_name(std::int16_t id) const;
    void validate_scalar_presentation(std::string_view map,std::int32_t id,std::int32_t value) const;
    std::size_t card_panel_bytes(std::span<const std::int16_t> cards, bool removing,
        bool inventory_full) const;
private:
    std::map<std::string,std::vector<RichonlineChanceEvent>,std::less<>> maps_;
    std::map<std::int16_t,std::string> names_;
    std::map<std::int32_t,std::string> strings_;
};
struct RichonlineChanceMoneyState {
    std::int32_t cash, deposit;
    bool operator==(const RichonlineChanceMoneyState&) const = default;
};
struct RichonlineChanceMoneyResult {
    Bytes packet;
    RichonlineChanceMoneyState after;
    // Category 0 returns false at exhaustion. The owner must run bankruptcy rules.
    bool client_continues_phase2;
    bool insolvent;
};
// Selection is a caller-owned server policy. Scalar is constrained to the two
// resource numeric columns as an explicit native-server bounds policy.
RichonlineChanceMoneyResult plan_richonline_chance_money(const RichonlineChanceEventTable&,
    std::string_view map, std::int32_t event, std::uint16_t game_id,
    std::int32_t scalar, RichonlineChanceMoneyState before,
    std::array<std::uint8_t,2> opaque6_7);
struct RichonlineChanceCardsResult {
    Bytes packet;
    RichonlineChanceInventory after;
};
// Category 4/5 inputs are card IDs; category 6 inputs are occupied slot indexes.
// Owner commits the returned snapshot atomically with the outgoing event.
RichonlineChanceCardsResult plan_richonline_chance_cards(const RichonlineChanceEventTable&,
    const RichonlineChanceResources&, std::string_view map, std::int32_t event,
    std::uint16_t game_id, std::span<const std::int32_t> values,
    const RichonlineChanceInventory& before, std::array<std::uint8_t,2> opaque6_7);
}

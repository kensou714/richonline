#pragma once

// 新版机会卡资源：校验地图事件与卡片关系，提供受限的单卡奖励与库存插入。

#include "codec.hpp"
#include <filesystem>
#include <map>
#include <set>
#include <string_view>

namespace richnet {
class RichonlineChanceResources;
class RichonlineChanceSingleCard {
public:
    std::int16_t event_id() const noexcept { return event_id_; }
    std::int16_t card_id() const noexcept { return card_id_; }
    std::string_view map() const noexcept { return map_; }
private:
    RichonlineChanceSingleCard(std::int16_t event, std::int16_t card, std::string_view map)
        : event_id_(event), card_id_(card), map_(map) {}
    std::int16_t event_id_, card_id_;
    std::string map_;
    friend class RichonlineChanceResources;
};
struct RichonlineChanceCardSlot {
    std::int16_t card_id = -1;
    std::int16_t count = 0;
    bool operator==(const RichonlineChanceCardSlot&) const = default;
};
using RichonlineChanceInventory = std::array<RichonlineChanceCardSlot,8>;
using RichonlineChanceMapMembership = std::map<std::string,std::set<std::int16_t>,std::less<>>;
class RichonlineChanceResources {
public:
    static RichonlineChanceResources parse(std::string_view news, std::string_view props,
        std::string_view combinations, RichonlineChanceMapMembership membership = {});
    static RichonlineChanceResources load(const std::filesystem::path& resource_root);
    RichonlineChanceSingleCard single_card(std::string_view map, std::int32_t event,
        std::int32_t card) const;
    // 保留机会事件的满仓异常；通用 add 满仓返回原库存，与客户端插入行为一致。
    RichonlineChanceInventory insert(const RichonlineChanceSingleCard& award,
        const RichonlineChanceInventory& inventory) const;
    RichonlineChanceInventory add(std::string_view map, std::int16_t card,
        std::int16_t count, const RichonlineChanceInventory& inventory) const;
    RichonlineChanceInventory discard(const RichonlineChanceInventory& inventory,
        std::int8_t slot) const;
    bool contains_card(std::int16_t card) const noexcept { return cards_.contains(card); }
    std::vector<std::int16_t> reward_candidates(std::string_view map) const {
        std::vector<std::int16_t> result;
        for(const auto card:cards_) if(automatic_card_eligible(map,card)) result.push_back(card);
        return result;
    }
    // NEW800A50 automatic use checks typeCARD and EMP membership. It does not
    // check Prop.enable; ordinary reward admission keeps contains_card.
    bool automatic_card_eligible(std::string_view map,std::int16_t card) const;
    bool is_card_type(std::int16_t card) const noexcept {return card_types_.contains(card);}
private:
    struct Event { std::int32_t category; std::set<std::int16_t> cards; };
    struct Combination { std::int16_t destination; std::map<std::int16_t,std::int32_t> sources; };
    std::map<std::string,std::vector<Event>,std::less<>> events_;
    std::set<std::int16_t> cards_;
    std::set<std::int16_t> card_types_;
    std::vector<Combination> combinations_;
    RichonlineChanceMapMembership membership_;
};
// 仅支持 4096 的类别 5；偏移 6/7 字节未被读取且含义未知，必须由调用方提供。
Bytes encode_richonline_chance_single_card(std::uint16_t game_id,
    const RichonlineChanceSingleCard& award, std::array<std::uint8_t,2> opaque6_7);
}

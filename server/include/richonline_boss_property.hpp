#pragma once

// 新版 BOSS 地产状态：购地、自有地产建造/升级及普通对手地产落点。

#include "richonline_boss_turns.hpp"
#include "richonline_construction_resources.hpp"
#include "richonline_game_ledger.hpp"
#include "richonline_combat_session.hpp"
#include <chrono>
#include <map>

namespace richnet {
class RichonlineBossProperty final {
public:
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;
    // 地图身份、建筑限制及初始地产均由实际选择的关卡提供。
    RichonlineBossProperty(const std::filesystem::path& resources_root,
        std::uint16_t game_id,std::array<std::uint32_t,2> initial_cash,const RichonlineBossStage& stage);
    RichonlineBossProperty(const std::filesystem::path& resources_root,
        std::uint16_t game_id,std::shared_ptr<RichonlineGameLedger> ledger,const RichonlineBossStage& stage);
    // 空值表示本模块不处理该落点，外层必须继续分派或明确拒绝，不能直接推进回合。
    bool validate_landing(const RichonlineLandingContext& context) const;
    std::optional<RichonlineLandingResult> land(const RichonlineLandingContext& context);
    void enable_human_decisions(std::chrono::milliseconds timeout,Now now);
    void configure_construction(std::array<std::int8_t,10> human_skills,
        std::shared_ptr<RichonlineBossCards> cards = {});
    RichonlineLandingResult decide(View request);
    // 超时按取消建造、拒绝升级或拒绝购地结束当前选择。
    std::optional<RichonlineLandingResult> poll();
    // NEW 7E51A0 mirrors the client's local research queue; it adds no wire reward.
    void advance_research(std::uint8_t actor);
    std::size_t pending_research_jobs() const noexcept;
    std::array<std::uint32_t,2> cash() const;
    std::optional<std::uint8_t> owner(std::int16_t property_ref) const noexcept;
    std::optional<std::uint32_t> price(std::int16_t property_ref) const noexcept;
    struct Building {
        std::int8_t kind=-1; std::uint8_t level=0;
        bool operator==(const Building&) const = default;
    };
    std::optional<Building> building(std::int16_t property_ref) const noexcept;
    struct CombatSnapshot {
        std::uint64_t revision;
        std::vector<RichonlineCombatBuildingView> buildings;
        bool decision_pending;
    };
    class PreparedCombat {
    public:
        const CombatSnapshot& expected() const noexcept { return expected_; }
        const std::vector<RichonlineCombatBuildingView>& after() const noexcept { return after_; }
    private:
        PreparedCombat()=default;
        CombatSnapshot expected_{};
        std::vector<RichonlineCombatBuildingView> after_;
        friend class RichonlineBossProperty;
    };
    // All methods share the session's serialization. No second ownership store.
    CombatSnapshot combat_snapshot() const;
    RichonlineCombatBuildingView combat_building_effect(const RichonlineCombatBuildingView&,
        RichonlineBossBlastBuildingEffect) const;
    PreparedCombat prepare_combat(const CombatSnapshot&,
        std::span<const RichonlineCombatBuildingView> after) const;
    bool combat_matches(const PreparedCombat&) const noexcept;
    // Prevalidated scalar-only apply. Invoke inside the session/ledger atomic
    // callback; false makes no mutation. Does not emit client-side damage again.
    bool commit_combat(const PreparedCombat&) noexcept;
private:
    RichonlineRoadTopology topology_;
    std::uint16_t game_id_;
    std::shared_ptr<RichonlineGameLedger> ledger_;
    struct Property {
        std::uint32_t price;
        std::optional<std::uint8_t> owner;
        Building building;
    };
    std::map<std::int16_t,Property> properties_;
    std::uint64_t property_revision_=0;
    std::chrono::milliseconds timeout_{0};
    Now now_;
    std::optional<Clock::time_point> deadline_;
    std::optional<std::int16_t> pending_property_;
    enum class Decision { purchase, construction, upgrade, research };
    Decision decision_=Decision::purchase;
    RichonlineConstructionResources construction_;
    std::array<std::int8_t,10> human_skills_{};
    std::shared_ptr<RichonlineBossCards> cards_;
    struct ResearchChoice { std::int16_t card; std::int8_t days; };
    struct ResearchJob { std::int16_t property; std::int8_t choice; std::int16_t card; std::int8_t days; };
    std::array<ResearchChoice,7> research_choices_{};
    std::array<std::optional<ResearchJob>,64> research_jobs_{};
    RichonlineLandingResult await_research(std::vector<Bytes> messages,std::int16_t property);
    RichonlineLandingResult complete_research(std::int8_t selection);
    RichonlineLandingResult owned_land(const RichonlineLandingContext& context,Property& property);
    RichonlineLandingResult complete_construction(std::int8_t selection);
    RichonlineLandingResult complete_upgrade(bool accept);
    RichonlineLandingResult complete_decision(bool accept);
};
}

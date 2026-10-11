#pragma once

// 新版道路拓扑与静态寻路：按地图邻接关系和成对传送点计算方向及落点。

#include "codec.hpp"
#include <filesystem>
#include <functional>
#include <optional>

namespace richnet {
struct OriginalEmp;
struct RichonlineRoadCell {
    std::int16_t position;
    std::int8_t terrain_type, static_type;
    std::int16_t property_ref;
    bool walkable;
    // 原生方向顺序：+width、-1、-width、+1；仅记录道路之间的边。
    std::array<std::optional<std::int16_t>, 4> neighbors;
};
class RichonlineRoadTopology {
public:
    std::uint32_t width() const noexcept { return width_; }
    std::uint32_t height() const noexcept { return height_; }
    const std::vector<RichonlineRoadCell>& cells() const noexcept { return cells_; }
    const RichonlineRoadCell& cell(std::int16_t position) const;
    std::optional<std::int16_t> portal_destination(std::int16_t position) const;
    const std::optional<std::array<std::int16_t,2>>& jail_positions() const noexcept { return jail_; }
private:
    RichonlineRoadTopology(std::uint32_t width, std::uint32_t height,
        std::vector<RichonlineRoadCell> cells);
    std::uint32_t width_, height_;
    std::vector<RichonlineRoadCell> cells_;
    std::optional<std::array<std::int16_t,2>> portals_;
    std::optional<std::array<std::int16_t,2>> jail_;
    friend RichonlineRoadTopology richonline_road_topology(const OriginalEmp& emp);
};
RichonlineRoadTopology richonline_road_topology(const OriginalEmp& emp);
RichonlineRoadTopology load_richonline_road_topology(const std::filesystem::path& path);

struct RichonlineRouteRequest {
    std::int16_t start;
    std::uint8_t heading;
    std::int32_t budget;
    // 显式首步方向必须连接相邻道路；未指定时优先沿当前朝向。
    std::optional<std::uint8_t> first_direction;
    bool portals_enabled = true;
    bool banks_enabled = false;
    bool scripted_reward = false;
};
struct RichonlineRoute {
    std::vector<std::uint8_t> directions;
    std::vector<std::int16_t> landings;
};
// 仅在存在多个非掉头候选时调用，候选按方向编号升序排列。
using RichonlineRouteChooser = std::function<std::size_t(std::size_t)>;
// Called once per new landing. The returned total budget may only grow, up to
// the client's 36 direction slots; the caller projects consumable road effects.
using RichonlineRouteBudget = std::function<std::int32_t(std::int16_t,std::int32_t,std::int32_t)>;
// 仅处理静态几何与成对的 61 类传送点，不含动态物件或追加步数效果。
// 9 类银行须由调用者显式启用并协调途中的暂停；67 类仍受保护。
RichonlineRoute build_richonline_route(const RichonlineRoadTopology& topology,
    const RichonlineRouteRequest& request, const RichonlineRouteChooser& chooser,
    const RichonlineRouteBudget& extend_budget = {});
}

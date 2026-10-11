#pragma once

// 新版建筑资源：读取建筑许可证、场景等级上限及合成角色建筑能力。
#include "codec.hpp"
#include <filesystem>
#include <string_view>

namespace richnet {
struct RichonlineBossStage;
class RichonlineClassicConstructionResources final {
public:
    static RichonlineClassicConstructionResources parse(std::string_view build);
    static RichonlineClassicConstructionResources load(const std::filesystem::path& client_root);
    std::int16_t licence(std::int8_t kind) const;
private:
    explicit RichonlineClassicConstructionResources(std::array<std::int16_t,5> ids):licence_ids_(ids) {}
    std::array<std::int16_t,5> licence_ids_;
};
struct RichonlineConstructionResources {
    std::int8_t default_kind;
    std::array<std::int16_t,10> licence_ids;
    std::array<std::uint8_t,10> scenario_caps;
    std::array<std::uint8_t,10> synthetic_skills;
    static RichonlineConstructionResources parse(std::string_view build, std::string_view boss);
    static RichonlineConstructionResources load(const std::filesystem::path& client_root);
    static RichonlineConstructionResources load(const std::filesystem::path& client_root,
        const RichonlineBossStage& stage);
};
}

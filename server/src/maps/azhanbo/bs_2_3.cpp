#include "../package_factories.hpp"

namespace richnet {
namespace {
RichonlineBossStage load(const std::filesystem::path& root,std::uint32_t category) {
    require_ordinary_boss_category(category);
    return load_richonline_boss_stage(root,"BS_2_3.emp",category);
}
}
const RichonlineMapPackage& richonline_azhanbo_2_3_package() {
    static const RichonlineMapPackage package{
        "azhanbo_2_3","BS_2_3.emp",false,std::nullopt,std::nullopt,
        RichonlineMapReadiness::partial,false,load,unimplemented_chance_policy,
        std::nullopt,std::nullopt,std::nullopt,std::nullopt,
        {{5,6,7,8,10,41,42,44,45,46,47,68,69,70}}};
    return package;
}
}


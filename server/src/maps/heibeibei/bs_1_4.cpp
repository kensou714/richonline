#include "../package_factories.hpp"

namespace richnet {
namespace {
RichonlineBossStage load(const std::filesystem::path& root,std::uint32_t category) {
    require_ordinary_boss_category(category);
    return load_richonline_boss_stage(root,"BS_1_4.emp",category);
}
}
const RichonlineMapPackage& richonline_heibeibei_1_4_package() {
    static const RichonlineMapPackage package{
        "heibeibei_1_4","BS_1_4.emp",false,std::nullopt,std::nullopt,
        RichonlineMapReadiness::partial,false,load,unimplemented_chance_policy,
        std::nullopt,std::nullopt,std::nullopt,std::nullopt,
        {{5,6,7,8,10,33,34,35,36,41,42,68,69,70}}};
    return package;
}
}


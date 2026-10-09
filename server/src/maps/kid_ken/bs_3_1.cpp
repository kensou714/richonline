#include "../package_factories.hpp"

namespace richnet {
namespace {
RichonlineBossStage load(const std::filesystem::path& root,std::uint32_t category) {
    require_ordinary_boss_category(category);
    return load_richonline_boss_stage(root,"BS_3_1.emp",category);
}
}
const RichonlineMapPackage& richonline_kid_ken_3_1_package() {
    static const RichonlineMapPackage package{
        "kid_ken_3_1","BS_3_1.emp",false,std::nullopt,std::nullopt,
        RichonlineMapReadiness::partial,false,load,unimplemented_chance_policy,
        std::nullopt,std::nullopt,std::nullopt,std::nullopt,
        {{5,6,7,8,10,28,37,38,39,41,42,57,58,68,69,70}}};
    return package;
}
}


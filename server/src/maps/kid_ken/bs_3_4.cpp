#include "../package_factories.hpp"

namespace richnet {
namespace {
RichonlineBossStage load(const std::filesystem::path& root,std::uint32_t category) {
    require_ordinary_boss_category(category);
    return load_richonline_boss_stage(root,"BS_3_4.emp",category);
}
}
const RichonlineMapPackage& richonline_kid_ken_3_4_package() {
    static const RichonlineMapPackage package{
        "kid_ken_3_4","BS_3_4.emp",false,std::nullopt,std::nullopt,
        RichonlineMapReadiness::partial,false,load,unimplemented_chance_policy,
        std::nullopt,std::nullopt,std::nullopt,std::nullopt,
        {{5,7,8,10,28,37,38,39,40,41,42,58,61,68,69,70}}};
    return package;
}
}


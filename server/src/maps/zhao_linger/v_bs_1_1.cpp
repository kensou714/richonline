#include "../package_factories.hpp"

namespace richnet {
namespace {
RichonlineBossStage load(const std::filesystem::path& root,std::uint32_t category) {
    if (category!=2) throw CodecError("richonline_map_package_missing");
    return load_richonline_boss_stage(root,"V_BS_1_1.emp",category);
}
RichonlineBossCardPolicy configure(const RichonlineBossCardPolicy& legacy) {
    auto result=legacy; result.map_name="V_BS_1_1.emp"; result.event_id=2; result.card_id=1038; return result;
}
}
const RichonlineMapPackage& richonline_zhao_linger_package() {
    static const RichonlineMapPackage package{"zhao_linger","V_BS_1_1.emp",true,2,1038,RichonlineMapReadiness::partial,false,load,configure,
        std::nullopt,std::nullopt,std::nullopt,std::nullopt,
        {{5,6,7,8,10,33,34,35,41,42,61,68,69,70}}};
    return package;
}
}

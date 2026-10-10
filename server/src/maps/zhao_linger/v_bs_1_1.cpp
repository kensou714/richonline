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
    static const RichonlineMapPackage package{"zhao_linger","V_BS_1_1.emp",true,2,1038,RichonlineMapReadiness::partial,true,load,configure,
        RichonlineMapChancePolicy{{1038,1039,1040,1041},true},
        RichonlineMapNpcPolicy{{0,1,2,3,4,6},4,1,2,5,3,true,{1038,1039},1000,
            RichonlineMapBadluckPolicy{4,RichonlineMapBadluckSelection::uniform_inventory_units_without_replacement}},
        RichonlineMapCombatPolicy{4,80,10,10,
            {RichonlineMapProjectile::missile,RichonlineMapProjectile::nuclear,RichonlineMapProjectile::safe_nuclear},
            true,true,true,false},
        RichonlineMapOpeningHand{{{1038,1},{1044,1}},{}},
        {{5,6,7,8,10,33,34,35,41,42,61,68,69,70}},
        RichonlineMapRawStatusPolicy::closed_boss_initial_status};
    return package;
}
}

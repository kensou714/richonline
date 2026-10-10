#include "../package_factories.hpp"

namespace richnet {
namespace {
RichonlineBossStage load(const std::filesystem::path& root,std::uint32_t category) {
    require_ordinary_boss_category(category);
    return load_richonline_boss_stage(root,"BS_1_4.emp",category);
}
RichonlineBossCardPolicy configure(const RichonlineBossCardPolicy& transport) {
    return {"BS_1_4.emp",17,1038,transport.opaque6_7};
}
}
const RichonlineMapPackage& richonline_heibeibei_1_4_package() {
    static const RichonlineMapPackage package{
        "heibeibei_1_4","BS_1_4.emp",false,17,1038,
        RichonlineMapReadiness::partial,true,load,configure,
        RichonlineMapChancePolicy{{1038,1039,1040,1041},true},
        RichonlineMapNpcPolicy{{0,1,2,3,4,6,7},4,1,2,5,3,true,{1038,1039},1000,
            RichonlineMapBadluckPolicy{4,RichonlineMapBadluckSelection::uniform_inventory_units_without_replacement}},
        RichonlineMapCombatPolicy{4,80,10,10,
            {RichonlineMapProjectile::missile,RichonlineMapProjectile::nuclear},
            true,true,true,false},
        RichonlineMapOpeningHand{{{1038,1},{1044,1}},{}},
        {{5,6,7,8,10,33,34,35,36,41,42,68,69,70}},
        RichonlineMapRawStatusPolicy::closed_boss_initial_status};
    return package;
}
}

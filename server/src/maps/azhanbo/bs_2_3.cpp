#include "../package_factories.hpp"

namespace richnet {
namespace {
RichonlineBossStage load(const std::filesystem::path& root,std::uint32_t category) {
    require_ordinary_boss_category(category);
    return load_richonline_boss_stage(root,"BS_2_3.emp",category);
}
RichonlineBossCardPolicy configure(const RichonlineBossCardPolicy& transport) {
    return {"BS_2_3.emp",8,1038,transport.opaque6_7};
}
}
const RichonlineMapPackage& richonline_azhanbo_2_3_package() {
    static const RichonlineMapPackage package{
        "azhanbo_2_3","BS_2_3.emp",false,8,1038,
        RichonlineMapReadiness::partial,true,load,configure,
        RichonlineMapChancePolicy{{1038,1039,1040,1079},true},
        RichonlineMapNpcPolicy{{0,1,2,3,4,6},4,1,2,5,3,true,{1038,1039},1000,
            RichonlineMapBadluckPolicy{4,RichonlineMapBadluckSelection::uniform_inventory_units_without_replacement}},
        RichonlineMapCombatPolicy{4,80,10,10,
            {RichonlineMapProjectile::missile,RichonlineMapProjectile::nuclear},
            true,true,true,false},
        RichonlineMapOpeningHand{{{1038,1},{1044,1}},{}},
        {{5,6,7,8,10,41,42,44,45,46,47,68,69,70}},
        RichonlineMapRawStatusPolicy::closed_boss_initial_status};
    return package;
}
}

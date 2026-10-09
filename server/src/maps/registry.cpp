#include "package_factories.hpp"
#include <vector>

namespace richnet {
const RichonlineMapPackage& legacy_richonline_map_package() { return richonline_heibeibei_package(); }
std::span<const RichonlineMapPackage* const> richonline_map_packages() {
    static const auto packages=[] {
        std::vector<const RichonlineMapPackage*> result{&richonline_heibeibei_package()};
        for (const auto& package:richonline_heibeibei_later_packages()) result.push_back(&package);
        for (const auto& package:richonline_azhanbo_packages()) result.push_back(&package);
        for (const auto& package:richonline_kid_ken_packages()) result.push_back(&package);
        result.push_back(&richonline_zhao_linger_package());
        return result;
    }();
    return packages;
}
const RichonlineMapPackage& find_richonline_map_package(std::string_view name,std::uint32_t category) {
    if (category==2 && name=="V_BS_1_2.emp") throw CodecError("richonline_map_package_resource_missing");
    for (const auto* package:richonline_map_packages())
        if (name==package->map_name && package->special_category==(category==2)) return *package;
    throw CodecError("richonline_map_package_missing");
}
}

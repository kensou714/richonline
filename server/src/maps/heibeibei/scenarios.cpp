#include "../package_factories.hpp"

namespace richnet {
std::span<const RichonlineMapPackage> richonline_heibeibei_later_packages() {
    static const RichonlineMapPackage packages[]{
        richonline_heibeibei_1_2_package(),
        richonline_heibeibei_1_3_package(),
        richonline_heibeibei_1_4_package()
    };
    return packages;
}
}

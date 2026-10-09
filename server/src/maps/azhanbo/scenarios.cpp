#include "../package_factories.hpp"

namespace richnet {
std::span<const RichonlineMapPackage> richonline_azhanbo_packages() {
    static const RichonlineMapPackage packages[]{
        richonline_azhanbo_2_1_package(),
        richonline_azhanbo_2_2_package(),
        richonline_azhanbo_2_3_package(),
        richonline_azhanbo_2_4_package()
    };
    return packages;
}
}

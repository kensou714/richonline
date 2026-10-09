#include "../package_factories.hpp"

namespace richnet {
std::span<const RichonlineMapPackage> richonline_kid_ken_packages() {
    static const RichonlineMapPackage packages[]{
        richonline_kid_ken_3_1_package(),
        richonline_kid_ken_3_2_package(),
        richonline_kid_ken_3_3_package(),
        richonline_kid_ken_3_4_package()
    };
    return packages;
}
}

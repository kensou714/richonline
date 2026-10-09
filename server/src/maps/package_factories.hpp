#pragma once

#include "richonline_map_package.hpp"

namespace richnet {
const RichonlineMapPackage& richonline_heibeibei_package();
const RichonlineMapPackage& richonline_zhao_linger_package();
const RichonlineMapPackage& richonline_heibeibei_1_2_package();
const RichonlineMapPackage& richonline_heibeibei_1_3_package();
const RichonlineMapPackage& richonline_heibeibei_1_4_package();
const RichonlineMapPackage& richonline_azhanbo_2_1_package();
const RichonlineMapPackage& richonline_azhanbo_2_2_package();
const RichonlineMapPackage& richonline_azhanbo_2_3_package();
const RichonlineMapPackage& richonline_azhanbo_2_4_package();
const RichonlineMapPackage& richonline_kid_ken_3_1_package();
const RichonlineMapPackage& richonline_kid_ken_3_2_package();
const RichonlineMapPackage& richonline_kid_ken_3_3_package();
const RichonlineMapPackage& richonline_kid_ken_3_4_package();
std::span<const RichonlineMapPackage> richonline_heibeibei_later_packages();
std::span<const RichonlineMapPackage> richonline_azhanbo_packages();
std::span<const RichonlineMapPackage> richonline_kid_ken_packages();
inline void require_ordinary_boss_category(std::uint32_t category) {
    if (category==2) throw CodecError("richonline_map_package_missing");
}
inline RichonlineBossCardPolicy unimplemented_chance_policy(const RichonlineBossCardPolicy&) {
    throw CodecError("richonline_map_chance_policy_unimplemented");
}
}

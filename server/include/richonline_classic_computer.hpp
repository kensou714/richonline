#pragma once
#include "richonline_classic_property.hpp"

namespace richnet {
// 电脑公司kind5在4013落点时本地收费，无独立选择请求或收费回包。
std::int32_t richonline_classic_computer_quote(const RichonlineClassicPropertyState&,
    std::uint32_t monetary_scale,std::shared_ptr<LuaServer> script={});
}

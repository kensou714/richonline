#include "richonline_property_resources.hpp"
#include "original_options.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <map>
#include <utility>

namespace richnet {
namespace {
std::int32_t integer(View record,std::size_t offset) {
    return std::bit_cast<std::int32_t>(read_le(record.subspan(offset,4)));
}
std::int8_t byte(std::int32_t value) {
    return std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(value));
}
std::int16_t word(std::int32_t value) {
    return std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(value));
}
std::optional<std::int16_t> coordinate(const OriginalEmp& emp,std::int32_t x,std::int32_t y) {
    if (x==-1) return {};
    // The client copies coordinate low words. Keep that conversion, then
    // reject coordinates that would escape the actual EMP array.
    const auto tx=static_cast<std::uint16_t>(x),ty=static_cast<std::uint16_t>(y);
    if (tx>=emp.width || ty>=emp.height)
        throw CodecError("richonline_property_resource_coordinate_invalid");
    return static_cast<std::int16_t>(static_cast<std::uint32_t>(ty)*emp.width+tx);
}
void validate_layout(const OriginalEmp& emp) {
    const auto count=static_cast<std::uint64_t>(emp.width)*emp.height;
    if (emp.version!=3 || emp.width==0 || emp.height==0 || count>32768 ||
        emp.terrain_offset<16 || emp.terrain_offset>emp.payload.size() || count>(emp.payload.size()-emp.terrain_offset)/64U ||
        emp.tile_types_offset<emp.terrain_offset+64U*count+4U ||
        emp.tile_types_offset>emp.payload.size() || count>(emp.payload.size()-emp.tile_types_offset)/4U ||
        emp.property_offset!=emp.tile_types_offset+4U*count || emp.property_offset>emp.payload.size() ||
        count>(emp.payload.size()-emp.property_offset)/88U ||
        emp.tail_offset!=emp.property_offset+88U*count)
        throw CodecError("richonline_property_resource_layout_invalid");
}
}
RichonlinePropertyResources richonline_property_resources(const OriginalEmp& emp,std::int32_t price_base) {
    validate_layout(emp);
    if (price_base<=0) throw CodecError("richonline_property_resource_price_base_invalid");
    RichonlinePropertyResources result{emp.width,emp.height,{}};
    const auto count=emp.width*emp.height;
    const View data(emp.payload);
    std::map<std::int16_t,std::size_t> indices;
    for (std::uint32_t id=0;id<count;++id) {
        const auto record=data.subspan(emp.property_offset+88U*id,88);
        const auto sprite=byte(integer(record,0));
        if (sprite!=11 && sprite!=12) continue;
        auto kind=byte(integer(record,12));
        const auto level=byte(integer(record,16));
        if (sprite==12 && kind==0) kind=-1;
        const auto price=static_cast<std::int64_t>(integer(record,56))*price_base;
        if (kind< -1 || level<0 || price<0 || price>std::numeric_limits<std::int32_t>::max())
            throw CodecError("richonline_property_resource_value_invalid");
        RichonlineInitialProperty property{static_cast<std::int16_t>(id),sprite,kind,
            static_cast<std::uint8_t>(level),std::nullopt,static_cast<std::uint32_t>(price),
            word(integer(record,84)),{coordinate(emp,integer(record,68),integer(record,72)),
                coordinate(emp,integer(record,76),integer(record,80))},{},{}};
        std::copy(record.begin(),record.end(),property.resource_record.begin());
        indices.emplace(property.id,result.properties.size());
        result.properties.push_back(std::move(property));
    }
    for (std::uint32_t tile=0;tile<count;++tile) {
        const auto record=data.subspan(emp.terrain_offset+64U*tile,64);
        if (byte(integer(record,0))==-1) continue;
        const auto ref=coordinate(emp,integer(record,56),integer(record,60));
        if (!ref) continue;
        const auto property=indices.find(*ref);
        if (property==indices.end()) throw CodecError("richonline_property_resource_reference_invalid");
        result.properties[property->second].road_tiles.push_back(static_cast<std::int16_t>(tile));
    }
    return result;
}
RichonlinePropertyResources load_richonline_property_resources(const std::filesystem::path& root,
    std::string_view map_name) {
    return richonline_property_resources(load_original_emp(root/"Map"/std::filesystem::path(map_name)),
        load_original_price_base(root/"Data"/"Option.kpd"));
}
}

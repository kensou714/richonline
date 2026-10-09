#include "original_map.hpp"
#include <bit>
#include <limits>
#include <set>

namespace richnet {
namespace {
std::int32_t integer(View data, std::size_t offset) {
    if (offset > data.size() || data.size()-offset < 4) throw CodecError("original_map_record_truncated");
    return std::bit_cast<std::int32_t>(read_le(data.subspan(offset,4)));
}
std::int8_t low_byte(std::int32_t value) {
    return std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(static_cast<std::uint32_t>(value) & 255U));
}
std::int16_t tile_at(const OriginalEmp& emp, std::int32_t x, std::int32_t y) {
    if (x < 0 || y < 0 || static_cast<std::uint32_t>(x) >= emp.width || static_cast<std::uint32_t>(y) >= emp.height)
        throw CodecError("original_map_coordinate_invalid");
    return static_cast<std::int16_t>(static_cast<std::uint32_t>(y)*emp.width+static_cast<std::uint32_t>(x));
}
void read_roads(OriginalMapResources& map) {
    const auto& emp = map.emp;
    const View data(emp.payload);
    const auto count = emp.width*emp.height;
    const auto special_x = integer(data,0), special_y = integer(data,4);
    const auto special = special_x == -1 || special_y == -1 ? -1 : tile_at(emp,special_x,special_y);
    for (std::uint32_t index = 0; index < count; ++index) {
        const auto record = emp.terrain_offset+64U*index;
        if (low_byte(integer(data,record)) == -1) continue;
        const auto x = integer(data,record+56), y = integer(data,record+60);
        const auto property = x == -1 ? std::int16_t{-1} : tile_at(emp,x,y);
        const auto type = static_cast<std::int32_t>(index) == special ? std::int8_t{7} : low_byte(integer(data,emp.tile_types_offset+4U*index));
        map.roads.push_back({static_cast<std::int16_t>(index),property,type});
    }
    if (map.roads.empty()) throw CodecError("original_map_roads_empty");
    std::set<std::int16_t> ids;
    for (const auto& road : map.roads) ids.insert(road.tile);
    constexpr std::array<std::array<int,2>,4> deltas{{{0,1},{-1,0},{0,-1},{1,0}}};
    for (const auto& road : map.roads) {
        const auto x = road.tile%static_cast<std::int32_t>(emp.width), y = road.tile/static_cast<std::int32_t>(emp.width);
        for (std::uint8_t direction = 0; direction < deltas.size(); ++direction) {
            const auto nx = x+deltas[direction][0], ny = y+deltas[direction][1];
            if (nx < 0 || ny < 0 || nx >= static_cast<std::int32_t>(emp.width) || ny >= static_cast<std::int32_t>(emp.height)) continue;
            const auto target = tile_at(emp,nx,ny);
            if (ids.contains(target)) map.edges.push_back({road.tile,target,direction});
        }
    }
}
void read_properties(OriginalMapResources& map, std::int32_t price_base) {
    if (price_base <= 0) throw CodecError("original_map_price_base_invalid");
    std::set<std::int16_t> ids;
    for (const auto& road : map.roads) if (road.property_id != -1) ids.insert(road.property_id);
    for (const auto id : ids) {
        const auto record = map.emp.property_offset+88U*static_cast<std::size_t>(id);
        const View data(map.emp.payload);
        const auto raw_sprite = integer(data,record);
        const auto sprite = low_byte(raw_sprite);
        auto kind = low_byte(integer(data,record+12));
        if (raw_sprite == -1 || (sprite == 12 && kind == 0)) kind = -1;
        const auto level = low_byte(integer(data,record+16));
        const auto price = static_cast<std::int64_t>(integer(data,record+56))*price_base;
        if (kind < -1 || level < 0 || price < 0 || price > std::numeric_limits<std::int32_t>::max())
            throw CodecError("original_map_property_invalid");
        map.properties.push_back({id,-1,sprite,kind,level,static_cast<std::int32_t>(price)});
    }
}
void read_tail(OriginalMapResources& map) {
    const auto tail = View(map.emp.payload).subspan(map.emp.tail_offset);
    const auto nonnegative = [&](std::size_t offset) {
        const auto value = integer(tail,offset);
        if (value < 0) throw CodecError("original_map_tail_value_invalid");
        return static_cast<std::uint32_t>(value);
    };
    map.human_funds = {nonnegative(104),nonnegative(108),nonnegative(112)};
    map.scale = nonnegative(116);
    std::size_t cursor = 120;
    const auto count = [&](std::size_t stride) {
        const auto size = nonnegative(cursor);
        cursor += 4;
        if (size > (tail.size()-cursor)/stride) throw CodecError("original_map_tail_array_truncated");
        return size;
    };
    const auto unknown_count = count(4);
    cursor += static_cast<std::size_t>(unknown_count)*4;
    const auto weights = count(8);
    if (weights > 32768) throw CodecError("original_map_card_count_invalid");
    std::set<std::int16_t> seen;
    for (std::uint32_t index = 0; index < weights; ++index) {
        const auto card = nonnegative(cursor), weight = nonnegative(cursor+4);
        if (card > 32767 || !seen.insert(static_cast<std::int16_t>(card)).second) throw CodecError("original_map_card_id_invalid");
        map.card_weights.push_back({static_cast<std::int16_t>(card),weight});
        cursor += 8;
    }
    if (weights != 0) for (auto* pool : {&map.pool_a_ids,&map.pool_b_ids}) {
        const auto pool_count = count(4);
        if (pool_count > weights) throw CodecError("original_map_pool_count_invalid");
        std::set<std::int16_t> pool_seen;
        for (std::uint32_t index = 0; index < pool_count; ++index) {
            const auto card = nonnegative(cursor);
            if (card > 32767 || !seen.contains(static_cast<std::int16_t>(card)) || !pool_seen.insert(static_cast<std::int16_t>(card)).second)
                throw CodecError("original_map_pool_card_id_invalid");
            pool->push_back(static_cast<std::int16_t>(card));
            cursor += 4;
        }
    }
    map.parsed_tail_bytes = cursor;
}
}
OriginalMapResources original_map_resources(OriginalEmp emp, std::int32_t price_base) {
    if (emp.version < 1 || emp.version > 3) throw CodecError("original_map_gameplay_version_unsupported");
    const auto cells = static_cast<std::uint64_t>(emp.width)*emp.height;
    if (emp.width == 0 || emp.height == 0 || cells > 32768 || emp.payload.size() < 16 ||
        emp.terrain_offset < 16 || emp.terrain_offset > emp.payload.size() ||
        64*cells > emp.payload.size()-emp.terrain_offset ||
        emp.tile_types_offset < emp.terrain_offset+64*cells+4 || emp.tile_types_offset > emp.payload.size() ||
        4*cells > emp.payload.size()-emp.tile_types_offset ||
        emp.property_offset != emp.tile_types_offset+4*cells || emp.property_offset > emp.payload.size() ||
        88*cells > emp.payload.size()-emp.property_offset || emp.tail_offset != emp.property_offset+88*cells)
        throw CodecError("original_map_layout_invalid");
    OriginalMapResources map{std::move(emp),{},{},{},{},0,{},{},{},0};
    read_roads(map);
    read_properties(map,price_base);
    read_tail(map);
    return map;
}
}

#include "richonline_property_resources.hpp"

#include <algorithm>
#include <bit>
#include <iostream>
#include <tuple>

namespace {
using namespace richnet;
void check(bool value,std::string_view reason) {
    if (!value) throw std::runtime_error(std::string(reason));
}
template<class F> void rejects(F action,std::string_view code) {
    try { action(); }
    catch(const CodecError& error) { check(error.what()==code,error.what()); return; }
    throw std::runtime_error("expected_property_resource_rejection");
}
void put(Bytes& bytes,std::size_t offset,std::uint32_t value) {
    for (unsigned i=0;i<4;++i) bytes.at(offset+i)=static_cast<std::uint8_t>(value>>(8U*i));
}
OriginalEmp fixture() {
    constexpr std::size_t terrain=16,types=terrain+4*64+4,properties=types+4*4,tail=properties+4*88;
    OriginalEmp result{3,2,2,{}, {},Bytes(tail),terrain,types,properties,tail};
    for (std::size_t id=0;id<4;++id) {
        put(result.payload,terrain+64*id,10);
        put(result.payload,terrain+64*id+56,id<2 ? 0U : 0xffffffffU);
        put(result.payload,terrain+64*id+60,0);
        put(result.payload,properties+88*id,0xffffffffU);
        put(result.payload,properties+88*id+68,0xffffffffU);
        put(result.payload,properties+88*id+76,0xffffffffU);
    }
    put(result.payload,properties,12); put(result.payload,properties+4,77);
    put(result.payload,properties+12,13); put(result.payload,properties+16,1);
    put(result.payload,properties+56,6); put(result.payload,properties+68,1);
    put(result.payload,properties+72,0); put(result.payload,properties+84,7);
    put(result.payload,properties+3*88,11); put(result.payload,properties+3*88+12,1);
    put(result.payload,properties+3*88+16,5); put(result.payload,properties+3*88+56,10);
    put(result.payload,properties+3*88+84,7);
    return result;
}
void synthetic() {
    auto emp=fixture();
    const auto parsed=richonline_property_resources(emp,10);
    check(parsed.width==2 && parsed.height==2 && parsed.properties.size()==2,"property_array_scan_wrong");
    const auto& initial=parsed.properties[0];
    check(initial.id==0 && initial.sprite_type==12 && initial.kind==13 && initial.level==1 &&
        !initial.owner && initial.price==60 && initial.district==7,"prebuilt_state_lost");
    check(initial.links==std::array<std::optional<std::int16_t>,2>{1,{}} &&
        initial.road_tiles==std::vector<std::int16_t>{0,1},"property_links_or_road_references_wrong");
    check(initial.resource_record[4]==77 && !initial.owner,"unknown_source_field_became_owner");
    check(parsed.properties[1].id==3 && parsed.properties[1].sprite_type==11 &&
        parsed.properties[1].kind==1 && parsed.properties[1].level==5 && parsed.properties[1].road_tiles.empty(),
        "unreferenced_small_property_lost");
    auto converted=emp;
    put(converted.payload,converted.property_offset,0x1000000c);
    put(converted.payload,converted.property_offset+12,0x1000000d);
    put(converted.payload,converted.property_offset+16,0x10000001);
    put(converted.payload,converted.property_offset+68,0x00010001);
    put(converted.payload,converted.property_offset+84,0x00010007);
    const auto low=richonline_property_resources(converted,10).properties[0];
    check(low.sprite_type==12 && low.kind==13 && low.level==1 && low.district==7 && low.links[0]==1,
        "client_low_byte_or_word_conversion_lost");
    auto empty=emp;
    put(empty.payload,empty.property_offset+12,0); put(empty.payload,empty.property_offset+16,0);
    check(richonline_property_resources(empty,10).properties[0].kind==-1,"large_empty_kind_not_normalized");
    rejects([&] { richonline_property_resources(emp,0); },"richonline_property_resource_price_base_invalid");
    auto invalid=emp; invalid.property_offset--;
    rejects([&] { richonline_property_resources(invalid,10); },"richonline_property_resource_layout_invalid");
    invalid=emp; invalid.payload.resize(emp.tail_offset-1);
    rejects([&] { richonline_property_resources(invalid,10); },"richonline_property_resource_layout_invalid");
    invalid=emp; put(invalid.payload,invalid.property_offset+56,0xffffffffU);
    rejects([&] { richonline_property_resources(invalid,10); },"richonline_property_resource_value_invalid");
    invalid=emp; put(invalid.payload,invalid.property_offset+56,0x7fffffffU);
    rejects([&] { richonline_property_resources(invalid,10); },"richonline_property_resource_value_invalid");
    invalid=emp; put(invalid.payload,invalid.property_offset+16,0xffffffffU);
    rejects([&] { richonline_property_resources(invalid,10); },"richonline_property_resource_value_invalid");
    invalid=emp; put(invalid.payload,invalid.property_offset+68,2);
    rejects([&] { richonline_property_resources(invalid,10); },"richonline_property_resource_coordinate_invalid");
    invalid=emp; put(invalid.payload,invalid.terrain_offset+56,1);
    rejects([&] { richonline_property_resources(invalid,10); },"richonline_property_resource_reference_invalid");
    invalid=emp; put(invalid.payload,invalid.terrain_offset+56,2);
    rejects([&] { richonline_property_resources(invalid,10); },"richonline_property_resource_coordinate_invalid");
}
using Prebuilt=std::tuple<std::int16_t,std::int8_t,std::uint8_t,std::uint32_t>;
struct MapExpectation { std::string_view name; std::size_t count; std::vector<Prebuilt> prebuilt; };
void real_resources(const std::filesystem::path& root) {
    const std::array<MapExpectation,13> maps{{
        {"BS_1_1.emp",5,{{168,13,1,100}}},
        {"BS_1_2.emp",6,{{86,14,1,100},{218,12,1,100}}},
        {"BS_1_3.emp",6,{{149,16,1,100},{154,12,1,100}}},
        {"BS_1_4.emp",5,{{152,14,2,100},{216,13,3,100}}},
        {"BS_2_1.emp",6,{{131,16,3,400},{186,12,3,400}}},
        {"BS_2_2.emp",5,{{148,13,2,400},{184,12,3,600},{213,16,2,400}}},
        {"BS_2_3.emp",6,{{122,13,2,200},{212,16,3,400}}},
        {"BS_2_4.emp",6,{{119,13,3,400},{215,14,3,400}}},
        {"BS_3_1.emp",5,{{132,14,2,100},{154,12,1,100},{235,13,2,100}}},
        {"BS_3_2.emp",4,{{104,14,3,100},{180,16,1,100},{184,12,1,100}}},
        {"BS_3_3.emp",4,{{119,12,1,100},{180,16,3,100},{219,11,2,100},{231,13,1,100}}},
        {"BS_3_4.emp",4,{{117,15,1,100},{155,12,1,100},{213,11,2,100},{218,13,2,100}}},
        {"V_BS_1_1.emp",6,{{153,13,3,600},{198,16,3,600}}}
    }};
    for (const auto& expected:maps) {
        const auto parsed=load_richonline_property_resources(root,expected.name);
        check(parsed.width==16 && parsed.height==18 && parsed.properties.size()==expected.count,
            std::string(expected.name)+": property_count_or_dimensions_wrong");
        std::vector<Prebuilt> prebuilt;
        for (const auto& property:parsed.properties) {
            check(!property.owner && property.sprite_type==12 && !property.road_tiles.empty(),
                std::string(expected.name)+": initial_owner_sprite_or_road_wrong");
            if (property.level>0) prebuilt.emplace_back(property.id,property.kind,property.level,property.price);
            else check(property.kind==-1,"ordinary_empty_building_kind_wrong");
        }
        check(prebuilt==expected.prebuilt,std::string(expected.name)+": exact_prebuilt_resource_state_wrong");
    }
    const auto first=load_richonline_property_resources(root,"BS_1_1.emp");
    const auto research=std::find_if(first.properties.begin(),first.properties.end(),[](const auto& p) { return p.id==168; });
    check(research!=first.properties.end() && research->road_tiles==std::vector<std::int16_t>{183,184},
        "BS_1_1_prebuilt_adjacent_roads_wrong");
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"NEW_resource_root_required"); synthetic(); real_resources(argv[1]);
        std::cout<<"PASS NEW 13-map prebuilt property initialization and boundaries\n";
    } catch(const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}

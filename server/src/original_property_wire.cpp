#include "original_property_wire.hpp"
#include <bit>
#include <type_traits>

namespace richnet {
namespace {
void binary_choice(std::int8_t choice) {
    if (choice != 0 && choice != 1) throw CodecError("original_property_binary_choice_invalid");
}
void building_choice(std::int8_t choice) {
    if (choice < 10 || choice > 20) throw CodecError("original_property_building_choice_invalid");
}
void research_choice(std::int8_t choice) {
    if (choice != -1 && (choice < 1 || choice > 7)) throw CodecError("original_property_research_choice_invalid");
}
}
OriginalPropertyRequest parse_original_property_request(View plain) {
    if (plain.size() < 2) throw CodecError("original_property_request_length_invalid");
    const auto opcode = read_le(plain.first(2));
    if (opcode != 32 && opcode != 33 && opcode != 55 && opcode != 56 && opcode != 57)
        throw CodecError("original_property_opcode_unsupported");
    if (plain.size() != (opcode == 32 ? 12U : 6U)) throw CodecError("original_property_request_length_invalid");
    const auto context = static_cast<std::uint16_t>(read_le(plain.subspan(2,2)));
    const auto choice = std::bit_cast<std::int8_t>(plain[opcode == 32 ? 8 : 4]);
    switch (opcode) {
    case 32:
        binary_choice(choice);
        return OriginalPropertyPurchase{context,static_cast<std::uint32_t>(read_le(plain.subspan(4,4))),
            choice,{plain[9],plain[10],plain[11]}};
    case 33: binary_choice(choice); return OriginalClassicUpgrade{context,choice,plain[5]};
    case 55: building_choice(choice); return OriginalBuildingChoice{context,choice,plain[5]};
    case 56: binary_choice(choice); return OriginalBossUpgrade{context,choice,plain[5]};
    case 57: research_choice(choice); return OriginalResearchSelection{context,choice,plain[5]};
    default: throw CodecError("original_property_opcode_unsupported");
    }
}
Bytes encode_original_property_result(std::uint16_t instance, const OriginalPropertyRequest& decision) {
    return std::visit([instance](const auto& value) {
        using T = std::decay_t<decltype(value)>;
        std::uint16_t opcode;
        if constexpr (std::is_same_v<T,OriginalPropertyPurchase>) { binary_choice(value.choice); opcode = 0x4020; }
        else if constexpr (std::is_same_v<T,OriginalClassicUpgrade>) { binary_choice(value.choice); opcode = 0x4021; }
        else if constexpr (std::is_same_v<T,OriginalBuildingChoice>) { building_choice(value.choice); opcode = 0x403d; }
        else if constexpr (std::is_same_v<T,OriginalBossUpgrade>) { binary_choice(value.choice); opcode = 0x403e; }
        else { research_choice(value.choice); opcode = 0x403f; }
        Bytes result; append_le(result,opcode,2); append_le(result,instance,2);
        result.push_back(std::bit_cast<std::uint8_t>(value.choice));
        return result;
    },decision);
}
}

#pragma once
#include "original_lobby_adapter.hpp"
#include <algorithm>
#include <bit>
#include <limits>

namespace original_exchange_test {
using namespace richnet;
inline void check(bool value,const char* reason) { if (!value) throw std::runtime_error(reason); }
inline Bytes number(double value) {
    Bytes data;
    const auto bits = std::bit_cast<std::uint64_t>(value);
    for (std::size_t i=0;i<8;++i) data.push_back(static_cast<std::uint8_t>(bits >> (8*i)));
    return data;
}
inline Frame request(double amount) {
    Bytes data;
    append_le(data,1,4); append_le(data,2,4);
    const auto encoded = number(amount); data.insert(data.end(),encoded.begin(),encoded.end());
    append_le(data,0,4); append_le(data,0,4);
    return {42,std::move(data)};
}
inline void balance(const Bytes& profile,std::size_t offset,double expected) {
    const auto bytes = number(expected);
    check(std::equal(bytes.begin(),bytes.end(),profile.begin()+static_cast<std::ptrdiff_t>(offset)),"exchange_profile_balance_wrong");
}
template<class Client>
nlohmann::json roundtrip(Client& client,Storage& storage,const nlohmann::json& account) {
    client.send(request(2));
    const auto result = client.receive();
    Bytes expected{1,0,0,0,0,0,0,0};
    for (const auto amount : {2.0,20.0}) {
        const auto bytes = number(amount); expected.insert(expected.end(),bytes.begin(),bytes.end());
    }
    check(result.wire_type == 79 && result.payload == expected,"exchange_success_response_wrong");
    const auto profile = client.receive();
    check(profile.wire_type == 23 && profile.payload.size() == 268,"exchange_profile_refresh_missing");
    check(read_le(View(profile.payload).first(4)) == account.at("role_id").get<std::uint32_t>(),"exchange_profile_wrong_role");
    balance(profile.payload,76,10.5); balance(profile.payload,84,2620); balance(profile.payload,92,500);
    const auto saved = storage.roles_for_username(account.at("username").get<std::string>()).at(0);
    check(saved.at("coins") == 10.5 && saved.at("gold") == 2620 && saved.at("bank") == 500,"exchange_commit_wrong");
    std::vector<Frame> invalid{{42,{}},{42,Bytes(23)},{42,Bytes(25)}};
    for (const auto amount : {0.0,-1.0,0.5,std::numeric_limits<double>::quiet_NaN(),std::numeric_limits<double>::infinity(),214748365.0})
        invalid.push_back(request(amount));
    for (const auto offset : {0U,4U,16U,20U}) {
        auto wrong = request(1); wrong.payload[offset] = 9; invalid.push_back(std::move(wrong));
    }
    for (const auto& input : invalid) {
        client.send(input); const auto response = client.receive();
        check(response.wire_type == 0xffffffffU && response.payload.size() == 136 &&
            read_le(View(response.payload).first(4)) == 42 &&
            read_le(View(response.payload).subspan(4,4)) == static_cast<std::uint32_t>(-10),"exchange_invalid_request_not_rejected");
    }
    client.send(request(11)); const auto insufficient = client.receive();
    check(insufficient.wire_type == 0xffffffffU && insufficient.payload.size() == 136 &&
        read_le(View(insufficient.payload).subspan(4,4)) == static_cast<std::uint32_t>(-124),"exchange_insufficient_response_wrong");
    check(storage.roles_for_username(account.at("username").get<std::string>()).at(0) == saved,"exchange_rejection_wrote_data");
    client.send({61,number(100)}); const auto deposit = client.receive();
    check(deposit.wire_type == 101 && deposit.payload == number(100),"exchange_failure_broke_bank_connection");
    const auto after = storage.roles_for_username(account.at("username").get<std::string>()).at(0);
    check(after.at("coins") == 10.5 && after.at("gold") == 2520 && after.at("bank") == 600,"exchange_then_bank_wrong");
    return after;
}
}

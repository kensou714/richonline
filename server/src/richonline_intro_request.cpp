#include "richonline_intro_request.hpp"
#include "richonline_lobby_error.hpp"

#include <windows.h>
#include <algorithm>

namespace richnet {
namespace {
std::string decode_intro(View payload) {
    if (payload.empty() || payload.size()>400 || payload.back()!=0 ||
        std::find(payload.begin(),payload.end()-1,0)!=payload.end()-1)
        throw CodecError("intro_request_string_invalid");
    if (payload.size()==2 && payload[0]==1) return {};
    const auto text=payload.first(payload.size()-1);
    if (text.empty()) return {};
    const auto* bytes=reinterpret_cast<const char*>(text.data());
    const auto length=static_cast<int>(text.size());
    const auto count=MultiByteToWideChar(950,MB_ERR_INVALID_CHARS,bytes,length,nullptr,0);
    if (count<=0) throw CodecError("intro_request_big5_invalid");
    std::wstring wide(static_cast<std::size_t>(count),L'\0');
    if (MultiByteToWideChar(950,MB_ERR_INVALID_CHARS,bytes,length,wide.data(),count)!=count)
        throw CodecError("intro_request_big5_invalid");
    const auto utf8_size=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide.data(),count,nullptr,0,nullptr,nullptr);
    if (utf8_size<=0) throw CodecError("intro_request_utf8_conversion_failed");
    std::string utf8(static_cast<std::size_t>(utf8_size),'\0');
    if (WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide.data(),count,utf8.data(),utf8_size,nullptr,nullptr)!=utf8_size)
        throw CodecError("intro_request_utf8_conversion_failed");
    if (!std::ranges::equal(client_text(utf8,ClientProfile::richonline),text))
        throw CodecError("intro_request_big5_not_canonical");
    return utf8;
}
}
RichonlineIntroSaveResult richonline_intro_request(Storage& accounts,
    RichonlineAuxiliaryStore& introductions,const std::string& username,
    std::uint32_t role_id,const Frame& request) {
    if (request.wire_type!=50) throw CodecError("intro_request_wire_invalid");
    try {
        const auto text=decode_intro(request.payload);
        const auto roles=accounts.roles_for_username(username);
        const auto role=std::find_if(roles.begin(),roles.end(),[&](const auto& item) {
            return item.at("role_id").template get<std::uint32_t>()==role_id;
        });
        if (role==roles.end()) throw StorageError("intro_role_not_owned");
        const auto encoded=client_text(role->at("name").get<std::string>(),ClientProfile::richonline);
        const auto name=richonline_auxiliary_name(std::string_view(reinterpret_cast<const char*>(encoded.data()),encoded.size()));
        const auto current=introductions.introduction(name);
        if (current.role_id!=role_id) throw StorageError("intro_role_identity_changed");
        static_cast<void>(introductions.save_introduction(username,role_id,text,current.revision,"client wire50 introduction edit"));
        return {};
    } catch (const std::runtime_error& error) {
        // -1 is our service refusal status. NEW's error scheduler routes it to
        // 830350 and disposes the pending request; no native intro enum is known.
        return {{richonline_lobby_failure(50,-1)},error.what()};
    }
}
}

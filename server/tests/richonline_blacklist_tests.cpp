#include "richonline_blacklist.hpp"
#include "blacklist_store.hpp"
#include <sqlite3.h>
#include <windows.h>
#include <algorithm>
#include <chrono>
#include <iostream>
#include <string_view>

namespace {
using namespace richnet;
void check(bool condition,std::string_view reason) {if(!condition) throw std::runtime_error(std::string(reason));}
Bytes bytes(std::string_view text) {return {text.begin(),text.end()};}
const auto owner=bytes("SyntheticRole");
const auto digest=bytes("0123456789abcdef0123456789abcdef");
const Bytes target{0xb4,0xfa,0xb8,0xd5};
Bytes request(std::uint32_t type,View who=owner,View key=digest,View name=target,bool enabled=true) {
    Bytes result{13,10};append_le(result,type,4);
    const auto size=type==4 ? 97U : (type==1 || type==2 ? 96U : 64U);
    append_le(result,size,4);result.resize(10+size,0);
    std::copy(who.begin(),who.end(),result.begin()+10);
    std::copy(key.begin(),key.end(),result.begin()+42);
    if(type==1 || type==2 || type==4) std::copy(name.begin(),name.end(),result.begin()+74);
    if(type==4) result[106]=enabled ? 1:0;
    return result;
}
void status(View packet,std::uint32_t type,std::uint32_t value) {
    check(packet.size()==(type==3 ? 14:46),"response total bytes");
    check(packet[0]==13 && packet[1]==10 && read_le(packet.subspan(2,4))==type,"response framing");
    check(read_le(packet.subspan(6,4))==(type==3 ? 4:36),"response payload bytes");
    check(read_le(packet.subspan(10,4))==value,"response status");
}
template<class F> void rejects(F action,std::string_view code) {
    try {action();}catch(const CodecError& error){check(error.what()==code,"wrong rejection");return;}
    throw std::runtime_error("missing rejection");
}
void list(View packet,View expected,bool enabled) {
    check(packet.size()==86,"entry plus terminator length");
    check(read_le(packet.subspan(2,4))==0 && read_le(packet.subspan(6,4))==33,"list entry framing");
    check(std::equal(expected.begin(),expected.end(),packet.begin()+10),"list exact raw name");
    check(packet[42]==(enabled ? 1:0),"list enabled flag");
    check(packet[43]==13 && packet[44]==10 && read_le(packet.subspan(49,4))==33 && packet[53]==0,"list terminator");
}
void cycle(const std::filesystem::path& path) {
    {
        BlacklistStore store(path);
        const auto empty=richonline_blacklist_response(store,request(0));
        check(empty.size()==43 && empty[10]==0,"empty list terminator");
        const auto added=richonline_blacklist_response(store,request(1));status(added,1,0);
        check(std::equal(target.begin(),target.end(),added.begin()+14),"add exact target echo");
        list(richonline_blacklist_response(store,request(0)),target,true);
        check(richonline_blacklist_response(store,request(4,owner,digest,target,false)).empty(),"type4 no response");
        list(richonline_blacklist_response(store,request(0)),target,false);
    }
    {
        BlacklistStore store(path);
        list(richonline_blacklist_response(store,request(0)),target,false);
        status(richonline_blacklist_response(store,request(3)),3,0xffffffffU);
        list(richonline_blacklist_response(store,request(0)),target,false);
        status(richonline_blacklist_response(store,request(1)),1,0);
        list(richonline_blacklist_response(store,request(0)),target,true);
        status(richonline_blacklist_response(store,request(2)),2,0);
        status(richonline_blacklist_response(store,request(2)),2,2);
        check(richonline_blacklist_response(store,request(0)).size()==43,"removal persisted and requests continue");
    }
}
void boundaries(const std::filesystem::path& path) {
    BlacklistStore store(path);
    for(std::uint32_t type=0;type<=4;++type) {
        auto truncated=request(type);truncated.pop_back();
        rejects([&]{richonline_blacklist_response(store,truncated);},"richonline_black_invalid_payload_length");
        auto extra=request(type);extra.push_back(0);
        rejects([&]{richonline_blacklist_response(store,extra);},"richonline_black_invalid_payload_length");
    }
    auto invalid=request(0);invalid[0]=0;
    rejects([&]{richonline_blacklist_response(store,invalid);},"richonline_black_invalid_magic");
    invalid=request(0);invalid[2]=5;
    rejects([&]{richonline_blacklist_response(store,invalid);},"richonline_black_type_unsupported");
    invalid=request(0);invalid[42]='G';
    rejects([&]{richonline_blacklist_response(store,invalid);},"richonline_black_digest_invalid");
    invalid=request(1);invalid[74]=0;
    rejects([&]{richonline_blacklist_response(store,invalid);},"richonline_black_name_empty");
    invalid=request(4);invalid[106]=2;
    rejects([&]{richonline_blacklist_response(store,invalid);},"richonline_black_enabled_invalid");
    rejects([&]{richonline_blacklist_response(store,request(4));},"richonline_black_target_missing");
    const Bytes full(32,0xfe);
    status(richonline_blacklist_response(store,request(1,owner,digest,full)),1,0);
    list(richonline_blacklist_response(store,request(0)),full,true);
    check(richonline_blacklist_response(store,request(0,bytes("OtherRole"))).size()==43,"owner namespace isolation");
    check(richonline_blacklist_response(store,request(0,owner,bytes("abcdef0123456789abcdef0123456789"))).size()==43,"account digest namespace isolation");
}
void database_failure_does_not_acknowledge_success(const std::filesystem::path& path) {
    BlacklistStore store(path);
    sqlite3* raw=nullptr;
    const auto encoded=path.u8string();
    check(sqlite3_open_v2(reinterpret_cast<const char*>(encoded.c_str()),&raw,SQLITE_OPEN_READWRITE,nullptr)==SQLITE_OK,"open failure fixture");
    const auto sql=[&](const char* text){check(sqlite3_exec(raw,text,nullptr,nullptr,nullptr)==SQLITE_OK,"failure fixture SQL");};
    sql("CREATE TRIGGER reject_add AFTER INSERT ON blacklist BEGIN SELECT RAISE(ABORT,'test insert failure'); END");
    bool rejected=false;
    try {richonline_blacklist_response(store,request(1));}catch(const BlacklistStoreError&){rejected=true;}
    check(rejected && store.list(owner,digest).empty(),"failed insert not acknowledged or persisted");
    sql("DROP TRIGGER reject_add");
    richonline_blacklist_response(store,request(1));
    richonline_blacklist_response(store,request(4,owner,digest,target,false));
    sql("CREATE TRIGGER reject_update AFTER UPDATE ON blacklist BEGIN SELECT RAISE(ABORT,'test update failure'); END");
    rejected=false;
    try {richonline_blacklist_response(store,request(1));}catch(const BlacklistStoreError&){rejected=true;}
    check(rejected,"failed atomic re-enable not acknowledged");
    list(richonline_blacklist_response(store,request(0)),target,false);
    sqlite3_close(raw);
}
}
int main() {
    try {
        const auto root=std::filesystem::absolute("richonline-blacklist-test-"+std::to_string(GetCurrentProcessId())+"-"+
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        cycle(root/"richonline-blacklist.sqlite3");boundaries(root/"boundaries.sqlite3");
        database_failure_does_not_acknowledge_success(root/"failure.sqlite3");
        std::filesystem::remove_all(root);
        std::cout<<"PASS NEW blacklist framing, persistence, enabled state, bounds and unsupported type3\n";
        return 0;
    }catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
}

#include "richonline_mall_service.hpp"
#include <windows.h>
#include <chrono>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
template<class Action>void rejects(Action action,const char* reason){try{action();}catch(const std::runtime_error& error){check(std::string_view(error.what())==reason,"wrong rejection");return;}throw std::runtime_error("expected rejection");}
Bytes bytes(std::string_view text){return {text.begin(),text.end()};}
Frame selection(std::int32_t mode){Bytes payload;append_le(payload,static_cast<std::uint32_t>(mode),4);return {16,std::move(payload)};}
Frame buy(std::uint32_t key){Bytes payload;for(auto word:std::array<std::uint32_t,4>{0,1,key,1})append_le(payload,word,4);return {18,std::move(payload)};}
RichonlineMallCatalog catalog(){return RichonlineMallCatalog::parse(bytes(
    "[PROP]\nindx=13\nname=Permanent\ntype=FUNC\nchType=FUNC_DT\nenable=true\nsaleLJ=true\npriceLJ=3\nscore=30\n"
    "[PROP]\nindx=14\nname=Timed\ntype=FUNC\nchType=FUNC_DT\nenable=true\nsaleLJ=true\npriceLJ=1\ndayJ=30\n"
    "[PROP]\nindx=15\nname=Bundle\ntype=FUNC\nchType=FUNC_DT\nenable=true\nsaleLJ=true\nfold=2\n"
    "[PROP]\nindx=16\nname=Level\ntype=FUNC\nchType=FUNC_DT\nenable=true\nsaleLJ=true\nlevel=2\n"),
    bytes("[F_J]\nprop=13\n[F_J]\nprop=14\n[F_J]\nprop=15\n[F_J]\nprop=16\n"));}
void failure(const RichonlineMallServiceReply& reply,std::string_view diagnostic){
    check(reply.diagnostic==diagnostic&&reply.frames.size()==1&&!reply.role_refresh,"failure diagnostic/shape");
    const auto& frame=reply.frames[0];check(frame.wire_type==0xffffffffU&&frame.payload.size()==9&&frame.payload.back()==0&&
        read_le(View(frame.payload).subspan(4,4))==static_cast<std::uint32_t>(-13),"missing NEW generic failure");
}
}
int main(){try{
    const auto path=std::filesystem::absolute("mall-service-"+std::to_string(GetCurrentProcessId())+"-"+
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))/"accounts.sqlite3";
    Storage storage(path);const auto initial=storage.dispatch("accounts.create",{{"username","Mall"},{"password","test"}}).at("account");
    const auto id=initial.at("role_id").get<std::int64_t>();
    storage.dispatch("accounts.update",{{"role_id",id},{"expected",{{"coins",initial.at("coins")}}},{"changes",{{"coins",10.0}}},{"reason","mall service fixture"}});
    const auto products=catalog();RichonlineMallService service(products,"unique-fixture-session",
        {0,0,-13,"compatibility: NEW87FD30/77 discards first/last DWORD; permanent resource has zero term"});
    check(!service.request(storage,"Mall",id,{20,{}},100),"unrelated packet consumed");
    failure(*service.request(storage,"Mall",id,buy(0x100d),100),"mall_purchase_without_selection");
    for(const auto [key,diagnostic]:std::array<std::pair<std::uint32_t,std::string_view>,3>{
        {{0x100e,"inventory_date_year_unrepresentable"},{0x100f,"mall_purchase_bundle_grant_unproven"},{0x1010,"mall_purchase_level_rule_unproven"}}}) {
        check(service.request(storage,"Mall",id,selection(-1),100)->frames.empty(),"selection must not emit invented ACK");
        failure(*service.request(storage,"Mall",id,buy(key),100),diagnostic);
    }
    service.request(storage,"Mall",id,selection(-2),100);failure(*service.request(storage,"Mall",id,buy(0x100d),100),"mall_existing_item_sale_rule_unproven");
    check(storage.roles_for_username("Mall")[0].at("coins")==10.0,"business rejection charged");
    service.request(storage,"Mall",id,selection(-1),100);
    const auto purchased=*service.request(storage,"Mall",id,buy(0x100d),100);
    check(purchased.diagnostic=="purchased_permanent"&&purchased.role_refresh&&purchased.role_refresh->at("coins")==7.0&&purchased.role_refresh->at("purchase_score")==30,"success balance refresh missing");
    check(purchased.frames.size()==1&&purchased.frames[0].wire_type==77&&purchased.frames[0].payload.size()==12&&
        read_le(View(purchased.frames[0].payload).subspan(4,4))==0x100d,"success77 key");
    check(storage.lobby_inventory("Mall",id,100).items==std::vector<std::uint32_t>{0x100d},"permanent item not persisted");
    service.request(storage,"Mall",id,selection(-1),100);failure(*service.request(storage,"Mall",id,buy(0x100d),100),"mall_inventory_conflict");
    check(storage.roles_for_username("Mall")[0].at("coins")==7.0,"duplicate charged");
    rejects([&]{service.request(storage,"Mall",id,{16,{0}},100);},"mall_selection16_size_invalid");
    auto malformed=buy(0x100d);malformed.payload.push_back(0);rejects([&]{service.request(storage,"Mall",id,malformed,100);},"mall_purchase18_size_invalid");
    std::cout<<"PASS NEW mall selection/no fake ACK, permanent atomic purchase/77/current role, timed/bundle/level/sale rejection and malformed boundaries\n";
    return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}

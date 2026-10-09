#include "richonline_mall_catalog.hpp"
#include <algorithm>
#include <iostream>
#include <stdexcept>

namespace {
using namespace richnet;
void check(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
Bytes bytes(std::string_view text){return {text.begin(),text.end()};}
template<class Action> void rejected(Action action,const char* reason){try{action();}catch(const CodecError& error){check(std::string_view(error.what())==reason,"wrong rejection");return;}throw std::runtime_error("expected rejection");}
}
int main(int argc,char** argv){try{
    const auto props=bytes("[PROP]\nindx=13\nname=Certificate\ntype=FUNC\nchType=FUNC_DT\nenable=true\nsaleLJ=true\nsaleLR=true\npriceLJ=1.5\npriceLR=200\nscore=15\ndayJ=30\ndayR=7\n[PROP]\nindx=14\nname=Disabled\ntype=FUNC\nchType=FUNC_DT\nenable=false\nsaleLJ=true\npriceLJ=999\n");
    const auto sales=bytes("[A_ZJ_J]\nprop=13\n[A_ZJ_R]\nprop=13\n[A_ZJ_J]\nprop=14\n");
    const auto catalog=RichonlineMallCatalog::parse(props,sales);
    const auto& points=catalog.purchasable(0x100d);
    check(points.price[0]==1.5&&points.price[1]==200&&points.fold==1&&points.score==15,"resource prices/default fold lost");
    check(points.term[0].days==30&&points.term[1].days==7,"currency durations conflated");
    check(&catalog.purchasable(0x200d)==&points,"gold product mismatch");
    rejected([&]{catalog.purchasable(0x100e);},"mall_purchase_product_unavailable");
    rejected([&]{catalog.purchasable(13);},"mall_purchase_currency_invalid");
    rejected([&]{catalog.purchasable(0x1100d);},"mall_purchase_metadata_unproven");
    rejected([&]{RichonlineMallCatalog::parse(props,bytes("[A_ZJ_J]\nprop=999\n"));},"mall_resource_sale_product_missing");
    rejected([&]{RichonlineMallCatalog::parse(props,bytes("[UNKNOWN_J]\nprop=13\n"));},"mall_resource_sale_group_invalid");
    const auto repeated=RichonlineMallCatalog::parse(props,bytes("[A_ZJ_J]\nprop=13\n[A_ZJ_J]\nprop=13\n"));
    check(repeated.offers().size()==2,"client resource repeated offers were dropped");
    auto invalid=props;
    const auto marker=std::search(invalid.begin(),invalid.end(),std::string_view("priceLJ=1.5").begin(),std::string_view("priceLJ=1.5").end());
    check(marker!=invalid.end(),"fixture price missing");
    std::copy_n("nan",3,marker+8);
    rejected([&]{RichonlineMallCatalog::parse(invalid,sales);},"mall_resource_price_invalid");
    if(argc==2){
        const auto actual=RichonlineMallCatalog::load(std::filesystem::path(argv[1]));
        check(actual.products().size()>100&&actual.offers().size()>100,"real catalog unexpectedly empty");
        std::size_t available=0,permanent=0;
        for(const auto& offer:actual.offers()){
            const auto& product=actual.products().at(offer.product);
            const auto mode=static_cast<std::uint32_t>(offer.currency);
            if(product.enabled&&product.sale.at(mode-1)){
                actual.purchasable(offer.product|(mode<<12U));++available;
                const auto& term=product.term.at(mode-1);
                if(term.years==0&&term.months==0&&term.days==0)++permanent;
            }
        }
        check(available>100,"real catalog availability lost");
        std::cout<<"NEW catalog products="<<actual.products().size()<<" offers="<<actual.offers().size()<<" available="<<available<<" permanent_offers="<<permanent<<'\n';
    }
    std::cout<<"PASS NEW mall resource prices, currency terms, sale allow-list, unavailable item and metadata rejection\n";
    return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}

#include "richonline_boss_shop.hpp"
#include <algorithm>
#include <iostream>

namespace {
using namespace richnet;
void check(bool ok,const char* reason) { if (!ok) throw std::runtime_error(reason); }
Bytes request(std::uint16_t opcode,std::int8_t index) {
    Bytes bytes; append_le(bytes,opcode,2); append_le(bytes,0x4567,2);
    bytes.push_back(static_cast<std::uint8_t>(index)); bytes.push_back(0xcc); return bytes;
}
RichonlineLandingContext shop_cell(const std::filesystem::path& root) {
    const auto map=load_richonline_road_topology(root/"Map"/"BS_1_1.emp");
    const auto& cell=map.cell(117);
    const auto degree=std::count_if(cell.neighbors.begin(),cell.neighbors.end(),[](const auto& edge) { return edge.has_value(); });
    check(cell.static_type==10 && cell.property_ref==-1 && degree==2,"actual_shop_fixture_changed");
    return {0,cell.position,cell.static_type,cell.property_ref,3,false,static_cast<std::uint8_t>(degree),false};
}
void run(const std::filesystem::path& root) {
    const auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
    const RichonlineBossCardPolicy policy{"BS_1_1.emp",17,1038,{0xa5,0x5a}};
    auto now=RichonlineBossShop::Clock::time_point{};
    const auto cell=shop_cell(root);
    RichonlineBossCards cards(resources,0x1234,policy);
    RichonlineBossShop shop(root,cards,0x1234,[&] { return now; },{0xa5,0x5a});
    const auto price=shop.price();
    check(price>0,"actual_card_price_missing");
    const auto opened=shop.land(cell,price);
    check(opened && opened->progress==RichonlineLandingProgress::await_event && opened->pending_opcode==0x30 &&
        opened->messages.size()==2 && opened->messages[0]==Bytes{0x13,0x40,0x34,0x12,117,0},"shop_opening_wrong");
    const auto& stock=opened->messages[1];
    check(stock.size()==77 && read_le(View(stock).first(2))==0x4030 && stock.back()==0,"shop_stock_header_wrong");
    for (std::size_t i=0;i<12;++i) {
        const auto slot=View(stock).subspan(4+6*i,6);
        check(read_le(slot.first(2))==static_cast<std::uint16_t>(shop.offers()[i].card_id) &&
            read_le(slot.subspan(2,2))==static_cast<std::uint16_t>(shop.offers()[i].count) &&
            slot[4]==0xa5 && slot[5]==0x5a,"shop_stock_policy_wrong");
    }
    check(std::count_if(shop.offers().begin(),shop.offers().end(),[](auto offer) { return offer.card_id!=-1; })==12,
        "shop_did_not_populate_twelve_resource_offers");
    const auto bought=shop.handle(request(0x30,0));
    check(bought.progress==RichonlineLandingProgress::await_event && bought.messages==std::vector<Bytes>{{0x31,0x40,0x34,0x12,0}} &&
        shop.points()==0 && cards.inventory()[0]==RichonlineChanceCardSlot{1038,1},"exact_points_purchase_wrong");
    const auto usable=cards.prepare_use({0x4567,0,0,4,0});
    check(usable && usable->die==4,"bought_card_not_usable");
    now+=std::chrono::seconds{9};
    const auto sold=shop.handle(request(0x31,0));
    check(sold.messages==std::vector<Bytes>{{0x32,0x40,0x34,0x12,0}} && shop.points()==price/2 &&
        cards.inventory()[0].card_id==-1 && shop.active(),"sale_did_not_update_shared_inventory");
    now+=std::chrono::seconds{1};
    const auto timeout=shop.poll();
    check(timeout && timeout->progress==RichonlineLandingProgress::complete &&
        timeout->messages==std::vector<Bytes>{{0x31,0x40,0x34,0x12,0xff}} && !shop.poll(),"shop_deadline_was_reset_or_repeated");
    check(shop.handle(request(0x30,-1)).messages.empty(),"late_exit_repeated_close");
    check(shop.land(cell,1234).has_value(),"shop_revisit_missing");
    const auto exited=shop.handle(request(0x30,-1));
    check(exited.progress==RichonlineLandingProgress::complete && shop.points()==1234,"manual_exit_changed_points");
    for (const auto starting_points : {price-1,price}) {
        RichonlineBossCards full(resources,0x1234,policy);
        if (starting_points==price) for (unsigned i=0;i<8;++i) full.commit_inventory(full.prepare_reward());
        const auto before=full.inventory();
        RichonlineBossShop rejected(root,full,0x1234,[&] { return now; });
        rejected.land(cell,starting_points);
        const auto result=rejected.handle(request(0x30,0));
        check(result.progress==RichonlineLandingProgress::complete && result.messages[0].back()==0xff &&
            full.inventory()==before && rejected.points()==starting_points,"invalid_purchase_mutated_assets");
    }
    RichonlineBossShop duplicate(root,cards,0x1234,[&] { return now; });
    duplicate.land(cell,2*price); duplicate.handle(request(0x30,0));
    const auto after=cards.inventory();
    check(duplicate.handle(request(0x30,0)).messages[0].back()==0xff && duplicate.points()==price && cards.inventory()==after,"duplicate_offer_charged_twice");
    const auto map=load_richonline_road_topology(root/"Map"/"BS_1_1.emp");
    const auto& branch=map.cell(178);
    auto junction=cell; junction.position=branch.position; junction.road_degree=3;
    check(branch.static_type==10 && duplicate.land(junction,1000).has_value(),"junction_shop_not_opened");
    duplicate.handle(request(0x30,-1));
    auto boss=cell; boss.synthetic_actor=true; boss.actor_slot=1;
    check(!duplicate.land(boss,1000),"human_shop_handled_boss");

    const auto rejected_transaction=[&](const Bytes& wire,std::uint32_t balance,const char* reason) {
        RichonlineBossCards inventory(resources,0x1234,policy);
        inventory.commit_inventory(inventory.prepare_reward());
        const auto before=inventory.inventory();
        RichonlineBossShop current(root,inventory,0x1234,[&] { return now; });
        check(current.land(cell,balance).has_value(),"rejection_fixture_did_not_open");
        const auto reply=current.handle(wire);
        check(reply.progress==RichonlineLandingProgress::complete &&
            reply.messages==std::vector<Bytes>{{0x31,0x40,0x34,0x12,0xff}} &&
            current.points()==balance && inventory.inventory()==before && !current.active(),reason);
    };
    rejected_transaction(Bytes{0x35,0,0x67,0x45},price,"refresh_changed_assets_or_left_turn_waiting");
    rejected_transaction(request(0x31,-1),price,"negative_sale_index_changed_assets");
    rejected_transaction(request(0x31,8),price,"out_of_range_sale_index_changed_assets");
    rejected_transaction(request(0x31,1),price,"empty_slot_sale_changed_assets");
    rejected_transaction(request(0x30,12),price,"out_of_range_offer_changed_assets");
    rejected_transaction(request(0x31,0),0x7fffffffU,"sale_overflow_changed_assets");

    RichonlineBossCards expired_cards(resources,0x1234,policy);
    RichonlineBossShop expired(root,expired_cards,0x1234,[&] { return now; });
    expired.land(cell,price);
    const auto expired_before=expired_cards.inventory();
    now+=std::chrono::seconds{10};
    const auto late_buy=expired.handle(request(0x30,0));
    check(late_buy.progress==RichonlineLandingProgress::complete && late_buy.messages[0].back()==0xff &&
        expired.points()==price && expired_cards.inventory()==expired_before && !expired.poll(),
        "order_at_deadline_charged_or_completed_twice");
    RichonlineBossCards ordinary_sale(resources,0x1234,policy);
    auto other_inventory=ordinary_sale.inventory(); other_inventory[7]={1044,3};
    ordinary_sale.commit_inventory(other_inventory);
    RichonlineBossShop general_shop(root,ordinary_sale,0x1234,[&] { return now; });
    general_shop.land(cell,150);
    const auto general_sold=general_shop.handle(request(0x31,7));
    check(general_sold.messages==std::vector<Bytes>{{0x32,0x40,0x34,0x12,7}} &&
        ordinary_sale.inventory()[7].card_id==-1 && general_shop.active(),"ordinary_card_sale_closed_instead_of_selling");
    const auto catalog=RichonlineShopCatalog::load(root,policy.map_name);
    check(general_shop.points()==150+catalog.price(1044)/2,"sale_multiplied_refund_by_count");
    RichonlineBossCards refresh_cards(resources,0x1234,policy);
    RichonlineBossShop refreshed(root,refresh_cards,0x1234,[&] { return now; });
    const auto configured_values=load_richonline_gold_charges(root/"Data"/"GoldCharge.kpd");
    check(refreshed.refresh_cost()==250 && configured_values.require(4)==250,"refresh_fee_not_from_actual_NEW_GoldCharge4");
    std::uint32_t reserve=1250; unsigned charges=0;
    refreshed.configure_refresh(configured_values,[&](std::uint32_t fee) {
        check(fee==250,"refresh_fee_not_from_NEW_GoldCharge4");
        if (reserve<fee) return false;
        reserve-=fee; ++charges; return true;
    });
    refreshed.land(cell,150);
    for (unsigned i=0;i<5;++i) {
        const auto reply=refreshed.handle(Bytes{0x35,0,0x67,0x45});
        check(reply.progress==RichonlineLandingProgress::await_event && reply.messages.size()==1 &&
            reply.messages[0].size()==77 && reply.messages[0].back()==1 && refreshed.points()==150,
            "refresh_did_not_replace_stock_or_charged_points");
    }
    check(reserve==0 && charges==5,"refresh_reserve_not_charged_once_each");
    check(refreshed.handle(Bytes{0x35,0,0x67,0x45}).progress==RichonlineLandingProgress::complete && charges==5,
        "refresh_limit_charged_sixth_request");
    RichonlineBossShop refused(root,refresh_cards,0x1234,[&] { return now; });
    std::uint32_t insufficient_reserve=249;
    refused.configure_refresh(configured_values,[&](std::uint32_t fee) {
        if (insufficient_reserve<fee) return false;
        insufficient_reserve-=fee; return true;
    });
    refused.land(cell,222);
    const auto refused_stock=refused.offers();
    const auto refused_reply=refused.handle(Bytes{0x35,0,0x67,0x45});
    check(refused_reply.messages==std::vector<Bytes>{{0x31,0x40,0x34,0x12,0xff}} &&
        refused.offers()==refused_stock && refused.points()==222 && insufficient_reserve==249,"failed_reserve_charge_replaced_stock");
    RichonlineBossShop deadline(root,refresh_cards,0x1234,[&] { return now; });
    unsigned deadline_charges=0;
    deadline.configure_refresh(configured_values,[&](std::uint32_t) { ++deadline_charges; return true; });
    deadline.land(cell,222); now+=std::chrono::seconds{9};
    deadline.handle(Bytes{0x35,0,0x67,0x45}); now+=std::chrono::seconds{1};
    check(deadline.poll().has_value() && deadline_charges==1 && !deadline.poll(),"refresh_restarted_shop_deadline");
    RichonlineBossShop varied(root,refresh_cards,0x1234,[&] { return now; });
    auto varied_values=configured_values; varied_values.values[4]=317;
    unsigned varied_charges=0;
    varied.configure_refresh(varied_values,[&](std::uint32_t fee) {
        check(fee==317,"refresh_cost_was_hardcoded"); ++varied_charges; return true;
    });
    varied.land(cell,222); varied.handle(Bytes{0x35,0,0x67,0x45});
    check(varied_charges==1 && varied.points()==222,"resource_mutation_refresh_failed");
    const auto last_selected=catalog.select([](std::size_t size) { return size-1; });
    check(last_selected.front()==catalog.offers().back() && last_selected.front()!=catalog.offers().front(),
        "injected_stock_selection_ignored");
    for (std::size_t i=0;i<last_selected.size();++i) for (std::size_t j=0;j<i;++j)
        check(last_selected[i].card_id!=last_selected[j].card_id,"stock_selected_duplicate_offer");
    for (std::size_t candidate=0;candidate<catalog.offers().size();++candidate) {
        RichonlineBossCards any_cards(resources,0x1234,policy);
        bool first=true;
        RichonlineBossShop any_shop(root,any_cards,0x1234,[&] { return now; },{0xa5,0x5a},
            [&](std::size_t) { const auto index=first ? candidate : 0; first=false; return index; });
        const auto offer=catalog.offers()[candidate]; const auto cost=catalog.price(offer.card_id);
        any_shop.land(cell,cost);
        const auto purchased=any_shop.handle(request(0x30,0));
        check(purchased.messages==std::vector<Bytes>{{0x31,0x40,0x34,0x12,0}} && any_shop.points()==0 &&
            any_cards.inventory()[0]==RichonlineChanceCardSlot{offer.card_id,offer.count},"resource_offer_purchase_failed");
        const auto returned=any_shop.handle(request(0x31,0));
        check(returned.messages==std::vector<Bytes>{{0x32,0x40,0x34,0x12,0}} && any_shop.points()==cost/2 &&
            any_cards.inventory()[0].card_id==-1,"resource_offer_sale_failed");
    }
    std::cout<<"verified resource offers="<<catalog.offers().size()<<", actual GoldCharge4 refresh fee=250\n";
}
void shared_ledger_transactions(const std::filesystem::path& root) {
    const auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
    RichonlineBossCards cards(resources,0x1234,{"BS_1_1.emp",17,1038,{0xa5,0x5a}});
    auto now=RichonlineBossShop::Clock::time_point{};
    const auto ledger=std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{{12345,6789,150,4321}});
    RichonlineBossShop shop(root,cards,0x1234,ledger,[&] { return now; });
    const auto cell=shop_cell(root);
    check(shop.land(cell).has_value(),"ledger_shop_did_not_open");
    ledger->adjust(0,ledger->snapshot(0),{0,0,91,0});
    const auto bought=shop.handle(request(0x30,0));
    check(bought.messages==std::vector<Bytes>{{0x31,0x40,0x34,0x12,0}} &&
        ledger->snapshot(0).funds==RichonlineGameFunds{12345,6789,241-shop.price(),4321} &&
        shop.points()==241-shop.price() && cards.inventory()[0].card_id==1038,
        "purchase_overwrote_external_ledger_change");
    ledger->adjust(0,ledger->snapshot(0),{13,17,19,23});
    const auto sold=shop.handle(request(0x31,0));
    check(sold.messages==std::vector<Bytes>{{0x32,0x40,0x34,0x12,0}} &&
        ledger->snapshot(0).funds==RichonlineGameFunds{12358,6806,260-shop.price()+shop.price()/2,4344} &&
        cards.inventory()[0].card_id==-1,"sale_overwrote_other_funds_or_cached_tickets");
    shop.handle(request(0x30,-1));
    check(shop.land(cell).has_value(),"ledger_shop_revisit_failed");
    const auto before=ledger->snapshot(0);
    ledger->adjust(0,before,{0,0,-static_cast<std::int64_t>(before.funds.tickets),0});
    const auto refused=shop.handle(request(0x30,0));
    check(refused.messages==std::vector<Bytes>{{0x31,0x40,0x34,0x12,0xff}} &&
        ledger->snapshot(0).funds.tickets==0 && cards.inventory()[0].card_id==-1,
        "purchase_used_stale_open_balance_after_external_spend");
    check(shop.points()==0,"shop_points_did_not_read_authoritative_ledger");
}
void landing_preflight(const std::filesystem::path& root) {
    const auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
    RichonlineBossCards cards(resources,0x1234,{"BS_1_1.emp",17,1038,{0xa5,0x5a}});
    const auto ledger=std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{{1234,567,150,890}});
    auto now=RichonlineBossShop::Clock::time_point{};
    unsigned selections=0,clock_reads=0;
    RichonlineBossShop shop(root,cards,0x1234,ledger,[&] { ++clock_reads; return now; },{0xa5,0x5a},
        [&](std::size_t) { ++selections; return std::size_t{0}; });
    const auto cell=shop_cell(root);
    const auto before=ledger->snapshot(0);
    const auto inventory=cards.inventory(); const auto offers=shop.offers();
    const auto& preflight=shop;
    for(unsigned i=0;i<3;++i) check(preflight.validate_landing(cell),"valid_shop_preflight_rejected");
    auto unsupported=cell; unsupported.synthetic_actor=true;
    check(!preflight.validate_landing(unsupported),"boss_preflight_claimed_human_shop");
    unsupported=cell; unsupported.road_degree=0;
    check(!preflight.validate_landing(unsupported),"invalid_road_preflight_supported");
    check(selections==0 && clock_reads==0 && !shop.active() && shop.offers()==offers &&
        ledger->snapshot(0)==before && cards.inventory()==inventory,"shop_preflight_mutated_state_or_rng");
    check(shop.land(cell).has_value() && selections==12 && clock_reads==1,"land_did_not_prepare_shop_once");
    const auto selected=shop.offers(); now+=std::chrono::seconds{9};
    bool active_rejected=false;
    try { preflight.validate_landing(cell); }
    catch(const CodecError& error) { active_rejected=std::string(error.what())=="richonline_shop_already_open"; }
    check(active_rejected && selections==12 && clock_reads==1 && shop.offers()==selected &&
        ledger->snapshot(0)==before && cards.inventory()==inventory,"active_preflight_changed_shop");
    check(!shop.poll(),"preflight_shortened_deadline");
    now+=std::chrono::seconds{1}; check(shop.poll().has_value(),"preflight_extended_deadline");
}
void stock_rng_transaction_boundaries(const std::filesystem::path& root) {
    const auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
    RichonlineBossCards cards(resources,0x1234,{"BS_1_1.emp",17,1038,{0xa5,0x5a}});
    const auto ledger=std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{{1234,567,150,890}});
    auto now=RichonlineBossShop::Clock::time_point{};
    enum class Draw { first,last,invalid };
    auto mode=Draw::first;
    unsigned draws=0,charges=0;
    RichonlineBossShop shop(root,cards,0x1234,ledger,[&]{return now;},{0xa5,0x5a},[&](std::size_t bound) {
        ++draws;
        if(mode==Draw::invalid)return bound;
        return mode==Draw::last?bound-1:0;
    });
    shop.enable_refresh([&](std::uint32_t){++charges;return true;});
    const auto cell=shop_cell(root);
    check(shop.land(cell).has_value() && draws==12,"first_visit_did_not_sample_twelve");
    const auto first=shop.offers();shop.handle(request(0x30,-1));mode=Draw::last;
    check(shop.land(cell).has_value() && draws==24 && shop.offers()!=first,"next_visit_reused_old_stock");
    const auto before_stock=shop.offers();const auto before_funds=ledger->snapshot(0);const auto before_cards=cards.inventory();
    mode=Draw::invalid;
    bool rejected=false;
    try { shop.handle(Bytes{0x35,0,0x67,0x45}); }
    catch(const CodecError& error){rejected=std::string_view(error.what())=="richonline_shop_random_invalid";}
    check(rejected && charges==0 && shop.active() && shop.offers()==before_stock &&
        ledger->snapshot(0)==before_funds && cards.inventory()==before_cards,"invalid_stock_rng_debited_or_partially_replaced");
    now+=std::chrono::seconds{10};
    check(shop.poll().has_value(),"failed_rng_changed_shop_deadline");
}
}
int main(int argc,char** argv) {
    try { check(argc==2,"resource_path_required"); run(argv[1]); shared_ledger_transactions(argv[1]); landing_preflight(argv[1]); stock_rng_transaction_boundaries(argv[1]); std::cout<<"PASS NEW human shop transactions and deadline\n"; }
    catch(const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}

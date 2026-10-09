#include "richonline_game_bank.hpp"
#include <bit>
#include <iostream>
#include <limits>

namespace {
using namespace richnet;
constexpr std::uint16_t game_id=0x1234,counter=0x4567;
constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
void check(bool ok,const char* reason) { if (!ok) throw std::runtime_error(reason); }
template<class F> void rejects(F action,const char* reason) {
    try { action(); } catch(const CodecError& error) {
        check(std::string(error.what())==reason,"unexpected_bank_error"); return;
    }
    throw std::runtime_error("expected_bank_rejection");
}
Bytes request(std::uint16_t action,std::int32_t amount) {
    Bytes bytes{0x27,0,0x67,0x45}; append_le(bytes,action,2);
    bytes.push_back(0xcc); bytes.push_back(0x9a);
    append_le(bytes,std::bit_cast<std::uint32_t>(amount),4); return bytes;
}
struct Fixture {
    RichonlineGameBank::Clock::time_point now{};
    RichonlineGameBank bank{game_id,{0xa5,{0xb6,0xc7}},[this] { return now; }};
    RichonlineGameBankEntry entry{0,173,counter,RichonlineGameBankVisit::passing,{700,300},false};
};
void parsing_preserves_signed_amount_and_padding() {
    // Given the NEW sender's exact12-byte record, unknown padding is data.
    const auto parsed=decode_richonline_game_bank_request(request(1,-3));
    check(parsed.calendar_counter==counter && parsed.action==RichonlineGameBankAction::withdraw &&
        parsed.amount==-3 && parsed.unassigned_padding==std::array<std::uint8_t,2>{0xcc,0x9a},"bank_request_fields_wrong");
    const auto pass=decode_richonline_game_bank_pass(Bytes{0x28,0,0x67,0x45,173,0});
    check(pass.calendar_counter==counter && pass.position==173,"pass_request_fields_wrong");
    for(std::size_t size=0;size<14;++size) if(size!=12) {
        auto bytes=request(0,1); bytes.resize(size);
        rejects([&] { decode_richonline_game_bank_request(bytes); },"richonline_game_bank_request_size");
    }
    for(std::size_t size=0;size<8;++size) if(size!=6)
        rejects([&] { decode_richonline_game_bank_pass(Bytes(size)); },"richonline_game_bank_pass_size");
    auto wrong=request(0,1); wrong[0]=0x29;
    rejects([&] { decode_richonline_game_bank_request(wrong); },"richonline_game_bank_request_opcode");
    rejects([&] { decode_richonline_game_bank_pass(Bytes{0x2a,0,1,0,1,0}); },"richonline_game_bank_pass_opcode");
    rejects([&] { decode_richonline_game_bank_request(request(3,1)); },"richonline_game_bank_action_invalid");
    rejects([&] { decode_richonline_game_bank_pass(Bytes{0x28,0,1,0,0xff,0xff}); },"richonline_game_bank_position_invalid");
}
void transactions_conserve_balances_and_resume_the_right_flow() {
    for(const auto visit:{RichonlineGameBankVisit::passing,RichonlineGameBankVisit::landing})
    for(const auto action:{std::uint16_t{0},std::uint16_t{1}}) {
        Fixture f; f.entry.visit=visit;
        const auto opened=f.bank.begin(f.entry);
        check(opened.messages==std::vector<Bytes>{{0x18,0x40,0x34,0x12,173,0,
            static_cast<std::uint8_t>(visit==RichonlineGameBankVisit::passing),0xa5}} &&
            opened.continuation==RichonlineGameBankContinuation::await_choice,"bank_open_or_visit_flag_wrong");
        // When the pending local actor deposits/withdraws100, there is one completion, not a new movement packet.
        const auto result=f.bank.handle(request(action,100));
        const auto expected=action==0 ? RichonlineGameBankBalance{600,400} : RichonlineGameBankBalance{800,200};
        check(result.entry.balance==f.entry.balance && result.after==expected && result.after.cash+result.after.deposit==1000 &&
            result.outcome==RichonlineGameBankOutcome::transferred && !f.bank.active(),"transaction_not_conserved");
        check(result.messages==std::vector<Bytes>{{0x2a,0x40,0x34,0x12,static_cast<std::uint8_t>(action),0,0xb6,0xc7,100,0,0,0}},
            "bank_transaction_wire_wrong");
        check(result.continuation==(visit==RichonlineGameBankVisit::passing ? RichonlineGameBankContinuation::resume_movement :
            RichonlineGameBankContinuation::continue_landing),"bank_completion_advances_wrong_flow");
        rejects([&] { f.bank.handle(request(action,100)); },"richonline_game_bank_not_pending");
        check(!f.bank.poll(),"transaction_repeated_by_timer");
    }
}
void invalid_transactions_exit_without_changing_money() {
    struct Case { std::uint16_t action; std::int32_t amount; RichonlineGameBankBalance balance; RichonlineGameBankOutcome outcome; };
    const Case cases[]{
        {0,-1,{700,300},RichonlineGameBankOutcome::rejected_amount},
        {0,std::numeric_limits<std::int32_t>::min(),{700,300},RichonlineGameBankOutcome::rejected_amount},
        {0,0,{700,300},RichonlineGameBankOutcome::rejected_amount},
        {1,0,{700,300},RichonlineGameBankOutcome::rejected_amount},
        {1,-1,{700,300},RichonlineGameBankOutcome::rejected_amount},
        {1,1,{700,0},RichonlineGameBankOutcome::insufficient_funds},
        {0,701,{700,300},RichonlineGameBankOutcome::insufficient_funds},
        {1,301,{700,300},RichonlineGameBankOutcome::insufficient_funds},
        {0,1,{1,maximum},RichonlineGameBankOutcome::destination_limit},
        {1,1,{maximum,1},RichonlineGameBankOutcome::destination_limit}};
    for(const auto& test:cases) {
        Fixture f; f.entry.balance=test.balance; f.bank.begin(f.entry);
        const auto result=f.bank.handle(request(test.action,test.amount));
        check(result.after==test.balance && result.outcome==test.outcome && !f.bank.active(),"rejected_bank_request_mutated_balance");
        check(result.messages==std::vector<Bytes>{{0x2a,0x40,0x34,0x12,2,0,0xb6,0xc7,0,0,0,0}},"rejection_did_not_use_safe_exit");
    }
}
void signed_balance_limit_and_full_transfer() {
    for(const auto action:{std::uint16_t{0},std::uint16_t{1}}) {
        Fixture f; f.entry.balance=action==0 ? RichonlineGameBankBalance{maximum,0} : RichonlineGameBankBalance{0,maximum};
        f.bank.begin(f.entry);
        const auto result=f.bank.handle(request(action,static_cast<std::int32_t>(maximum)));
        check(result.after==(action==0 ? RichonlineGameBankBalance{0,maximum} : RichonlineGameBankBalance{maximum,0}),
            "full_transfer_at_signed_limit_failed");
    }
}
void timeout_exit_and_synthetic_do_not_wait_forever() {
    for(const bool late_click:{false,true}) {
        Fixture f; f.bank.begin(f.entry); f.now+=std::chrono::milliseconds{7999};
        check(!f.bank.poll(),"bank_timeout_early"); f.now+=std::chrono::milliseconds{1};
        const auto result=late_click ? f.bank.handle(request(0,100)) : *f.bank.poll();
        check(result.outcome==RichonlineGameBankOutcome::timed_out && result.after==f.entry.balance &&
            result.messages[0][4]==2 && !f.bank.active(),"bank_timeout_applied_late_transfer");
    }
    Fixture f; f.bank.begin(f.entry);
    const auto exit=f.bank.handle(request(2,999));
    check(exit.after==f.entry.balance && exit.messages[0][8]==0 && exit.outcome==RichonlineGameBankOutcome::exited,
        "exit_amount_was_interpreted_as_money");
    for(const auto visit:{RichonlineGameBankVisit::passing,RichonlineGameBankVisit::landing}) {
        Fixture boss; boss.entry.actor_slot=1; boss.entry.synthetic_actor=true; boss.entry.visit=visit;
        const auto result=boss.bank.begin(boss.entry);
        check(result.messages.size()==2 && result.messages[0][0]==0x18 && result.messages[1][0]==0x2a &&
            result.messages[1][4]==2 && result.after==boss.entry.balance && !boss.bank.active() &&
            result.outcome==RichonlineGameBankOutcome::synthetic_exit,"synthetic_bank_skipped_flag_sync_or_waited_for_ui");
        check(result.messages[0][6]==static_cast<std::uint8_t>(visit==RichonlineGameBankVisit::passing) &&
            result.continuation==(visit==RichonlineGameBankVisit::passing ? RichonlineGameBankContinuation::resume_movement :
                RichonlineGameBankContinuation::continue_landing),"synthetic_bank_wrong_continuation");
    }
}
void stale_or_malformed_requests_preserve_pending_decision() {
    Fixture f; f.bank.begin(f.entry);
    rejects([&] { f.bank.begin(f.entry); },"richonline_game_bank_already_pending");
    auto stale=request(0,100); stale[2]=0x66;
    rejects([&] { f.bank.handle(stale); },"richonline_game_bank_counter_mismatch");
    rejects([&] { f.bank.handle(Bytes{0x27,0}); },"richonline_game_bank_request_size");
    check(f.bank.active(),"invalid_request_consumed_pending_bank");
    const auto done=f.bank.handle(request(2,0));
    check(done.after==f.entry.balance,"invalid_request_changed_ledger");
    f.entry.balance.cash=maximum+1;
    rejects([&] { f.bank.begin(f.entry); },"richonline_game_bank_balance_invalid");
    check(!f.bank.active(),"invalid_entry_created_pending_bank");
    f.entry.balance={700,300}; f.entry.position=-1;
    rejects([&] { f.bank.begin(f.entry); },"richonline_game_bank_position_invalid");
    f.entry.position=173; f.entry.actor_slot=8;
    rejects([&] { f.bank.begin(f.entry); },"richonline_game_bank_actor_invalid");
    f.entry.actor_slot=0; f.entry.visit=static_cast<RichonlineGameBankVisit>(99);
    rejects([&] { f.bank.begin(f.entry); },"richonline_game_bank_visit_invalid");
    rejects([&] { RichonlineGameBank bad(game_id,{0,{0,0}},{}); },"richonline_game_bank_clock_required");
}
}
int main() {
    try {
        parsing_preserves_signed_amount_and_padding(); transactions_conserve_balances_and_resume_the_right_flow();
        invalid_transactions_exit_without_changing_money(); signed_balance_limit_and_full_transfer();
        timeout_exit_and_synthetic_do_not_wait_forever(); stale_or_malformed_requests_preserve_pending_decision();
        std::cout<<"PASS NEW game bank parsing, conserved transfers, safe exit and continuation\n";
    } catch(const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}

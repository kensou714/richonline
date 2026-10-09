#include "bank.hpp"
#include "storage.hpp"
#include <sqlite3.h>
#include <windows.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <future>
#include <iostream>
#include <limits>
#include <memory>
#include <string_view>
#include <vector>

namespace {
using nlohmann::json;
using richnet::BankDirection;
using richnet::BankLimits;
using richnet::BankStatus;
constexpr BankLimits limits{10.0, 5.0, 1000.0};

void check(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

class Database {
public:
    explicit Database(const std::filesystem::path& path) {
        sqlite3* raw = nullptr;
        const auto encoded = path.u8string();
        const int result = sqlite3_open(reinterpret_cast<const char*>(encoded.c_str()), &raw);
        db_.reset(raw);
        check(result == SQLITE_OK, "open bank fixture");
        check(sqlite3_busy_timeout(db_.get(), 5000) == SQLITE_OK, "set fixture timeout");
    }
    void exec(const char* command) {
        check(sqlite3_exec(db_.get(), command, nullptr, nullptr, nullptr) == SQLITE_OK,
              "execute bank fixture SQL");
    }
    json rows(const char* command) {
        sqlite3_stmt* raw = nullptr;
        const int prepared = sqlite3_prepare_v2(db_.get(), command, -1, &raw, nullptr);
        std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> statement(raw, sqlite3_finalize);
        check(prepared == SQLITE_OK, "prepare bank fixture query");
        auto result = json::array();
        int status;
        while ((status = sqlite3_step(statement.get())) == SQLITE_ROW) {
            auto row = json::array();
            for (int column = 0; column < sqlite3_column_count(statement.get()); ++column) {
                const auto* value = sqlite3_column_text(statement.get(), column);
                row.push_back(value ? json(reinterpret_cast<const char*>(value)) : json(nullptr));
            }
            result.push_back(row);
        }
        check(status == SQLITE_DONE, "finish bank fixture query");
        return result;
    }
private:
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> db_{nullptr, sqlite3_close};
};

struct Fixture {
    std::filesystem::path path;
    richnet::Storage store;
    std::int64_t role_id;
    explicit Fixture(const std::filesystem::path& file) : path(file),
        store(file, richnet::ClientProfile::original),
        role_id(store.dispatch("accounts.create", {{"username", "BankOwner"},
            {"password", "bank-test"}}).at("account").at("role_id").get<std::int64_t>()) {
        Database(path).exec("UPDATE roles SET gold=200.0,bank=100.0");
    }
    json role() { return store.roles_for_username("BankOwner").at(0); }
    json state() {
        Database db(path);
        return json::array({role(), db.rows("SELECT * FROM audit ORDER BY id"),
            db.rows("SELECT * FROM operations ORDER BY operation_id")});
    }
    BankStatus transfer(BankDirection direction, double amount, BankLimits policy = limits) {
        return store.transfer_bank("BankOwner", role_id, {direction, amount, policy});
    }
    void balances(double gold, double bank) {
        const auto current = role();
        check(current.at("gold") == gold && current.at("bank") == bank, "bank balances mismatch");
        check(current.at("coins") == 10000.0, "bank transfer changed coins");
    }
};

template<class Action>
void rejects(Action action, std::string_view code) {
    try { action(); }
    catch (const richnet::StorageError& error) {
        check(error.what() == code, "wrong bank rejection code");
        return;
    }
    throw std::runtime_error("expected bank rejection missing");
}

void successful_transfers(const std::filesystem::path& path) {
    json final_role;
    {
    Fixture fixture(path);
    check(fixture.transfer(BankDirection::deposit, 25.5) == BankStatus::success, "deposit succeeds");
    fixture.balances(174.5, 125.5);
    check(fixture.transfer(BankDirection::withdraw, 5.5) == BankStatus::success, "withdraw succeeds");
    fixture.balances(180.0, 120.0);
    const auto audit = Database(path).rows("SELECT field,CAST(old_value AS REAL),CAST(new_value AS REAL),"
        "reason FROM audit WHERE source='native-bank' ORDER BY id");
    check(audit.size() == 4, "each transfer has two audit entries");
    auto expected = json::array({json::array({"gold", "200.0", "174.5", "deposit"}),
        json::array({"bank", "100.0", "125.5", "deposit"}),
        json::array({"gold", "174.5", "180.0", "withdraw"}),
        json::array({"bank", "125.5", "120.0", "withdraw"})});
    for (const auto& row : expected)
        check(std::find(audit.begin(), audit.end(), row) != audit.end(), "audit amounts and reason");
    check(Database(path).rows("SELECT count(*) FROM audit WHERE source='native-bank' AND "
        "username='BankOwner' AND role_id=1 AND operation_id=''") == json::array({json::array({"4"})}),
        "bank audit identity and empty operation id");
    final_role = fixture.role();
    }
    richnet::Storage reopened(path, richnet::ClientProfile::original);
    check(reopened.roles_for_username("BankOwner").at(0) == final_role, "committed transfers persist");
}

void rejected_transfers(const std::filesystem::path& path) {
    Fixture fixture(path);
    const auto before = fixture.state();
    const std::array invalid{0.0, -1.0, std::numeric_limits<double>::quiet_NaN(),
        std::numeric_limits<double>::infinity(), -std::numeric_limits<double>::infinity(),
        2147483648.0};
    for (const auto direction : {BankDirection::deposit, BankDirection::withdraw}) {
        for (double amount : invalid)
            check(fixture.transfer(direction, amount) == BankStatus::invalid_amount, "invalid amount rejected");
        check(fixture.transfer(direction, 4.0) == BankStatus::invalid_amount, "below minimum rejected");
    }
    check(fixture.transfer(BankDirection::deposit, 9.0) == BankStatus::invalid_amount,
          "deposit uses its own minimum");
    check(fixture.transfer(BankDirection::deposit, 201.0) == BankStatus::insufficient_funds,
          "deposit cannot overdraw gold");
    check(fixture.transfer(BankDirection::withdraw, 101.0) == BankStatus::insufficient_funds,
          "withdraw cannot overdraw bank");
    check(fixture.transfer(BankDirection::deposit, 101.0, {10.0, 5.0, 200.0}) == BankStatus::capacity_exceeded,
          "deposit cannot exceed capacity");
    check(fixture.state() == before, "rejected transfers leave balances and audit unchanged");
}

void ownership_and_limits(const std::filesystem::path& path) {
    Fixture fixture(path);
    fixture.store.dispatch("accounts.create", {{"username", "OtherOwner"}, {"password", "other-test"}});
    const auto before = fixture.state();
    for (const auto username : {"OtherOwner", "missing", "bankowner"})
        rejects([&] { fixture.store.transfer_bank(username, fixture.role_id,
            {BankDirection::deposit, 10.0, limits}); }, "bank_role_not_owned");
    rejects([&] { fixture.store.transfer_bank("BankOwner", 999,
        {BankDirection::deposit, 10.0, limits}); }, "bank_role_not_owned");
    const double nan = std::numeric_limits<double>::quiet_NaN();
    const double inf = std::numeric_limits<double>::infinity();
    const std::array bad_limits{BankLimits{-1, 5, 1000}, BankLimits{10, -1, 1000},
        BankLimits{10, 5, -1}, BankLimits{nan, 5, 1000}, BankLimits{10, nan, 1000},
        BankLimits{10, 5, nan}, BankLimits{inf, 5, 1000}, BankLimits{10, inf, 1000},
        BankLimits{10, 5, inf}, BankLimits{1001, 5, 1000}, BankLimits{10, 1001, 1000}};
    for (const auto policy : bad_limits)
        rejects([&] { fixture.transfer(BankDirection::deposit, 10.0, policy); }, "bank_limits_invalid");
    check(fixture.state() == before, "ownership and limits failures have no writes");
}

void boundaries_and_repetition(const std::filesystem::path& path) {
    Fixture fixture(path);
    for (int repeat = 0; repeat < 2; ++repeat)
        check(fixture.transfer(BankDirection::deposit, 10.0) == BankStatus::success,
              "identical transfers are independent requests");
    fixture.balances(180.0, 120.0);
    check(fixture.transfer(BankDirection::withdraw, 5.0) == BankStatus::success, "withdraw minimum accepted");
    check(fixture.transfer(BankDirection::deposit, 185.0, {0, 0, 300}) == BankStatus::success,
          "exact cash and capacity boundaries accepted");
    fixture.balances(0.0, 300.0);
    check(fixture.transfer(BankDirection::withdraw, 300.0, {0, 0, 300}) == BankStatus::success,
          "entire bank balance can be withdrawn");
    fixture.balances(300.0, 0.0);
    check(fixture.transfer(BankDirection::deposit, 1.0, {0, 0, 0}) == BankStatus::capacity_exceeded,
          "zero capacity is valid and rejects deposits");
    check(Database(path).rows("SELECT count(*) FROM audit WHERE source='native-bank'") ==
        json::array({json::array({"10"})}), "repeated requests each append audit pairs");
    check(Database(path).rows("SELECT count(*) FROM operations") == json::array({json::array({"0"})}),
          "bank transfers do not create deduplication operations");
    Database(path).exec("UPDATE roles SET gold=2147483647.0,bank=0.0");
    check(fixture.transfer(BankDirection::deposit, 2147483647.0, {0, 0, 2147483647.0}) == BankStatus::success,
          "INT32_MAX transfer accepted");
    fixture.balances(0.0, 2147483647.0);
}

void audit_failure_rolls_back(const std::filesystem::path& path) {
    Fixture fixture(path);
    Database(path).exec("CREATE TRIGGER reject_second_bank_audit BEFORE INSERT ON audit "
        "WHEN NEW.source='native-bank' AND (SELECT count(*) FROM audit WHERE source='native-bank')=1 "
        "BEGIN SELECT RAISE(ABORT,'injected_bank_audit_failure'); END;");
    const auto before = fixture.state();
    bool rejected = false;
    try { fixture.transfer(BankDirection::deposit, 10.0); }
    catch (const richnet::StorageError&) { rejected = true; }
    check(rejected, "audit trigger must abort transfer");
    check(fixture.state() == before, "second audit failure rolls back both balances and first audit");
    Database(path).exec("DROP TRIGGER reject_second_bank_audit");
    check(fixture.transfer(BankDirection::deposit, 10.0) == BankStatus::success,
          "connection remains usable after rollback");
}

void precision_rejection(const std::filesystem::path& path) {
    Fixture fixture(path);
    const std::array setups{"UPDATE roles SET gold=9007199254740992.0,bank=100.0",
        "UPDATE roles SET gold=100.0,bank=9007199254740992.0",
        "UPDATE roles SET gold=1.0e100,bank=100.0", "UPDATE roles SET gold=100.0,bank=1.0e100"};
    for (const char* setup : setups) {
        Database(path).exec(setup);
        const auto before = fixture.state();
        for (const auto direction : {BankDirection::deposit, BankDirection::withdraw})
            check(fixture.transfer(direction, 1.5, {0, 0, 1.0e101}) == BankStatus::invalid_amount,
                  "rounded or lost balance movement rejected");
        check(fixture.state() == before, "precision failure has no writes");
    }
}

void concurrent_transfers(const std::filesystem::path& path, BankDirection direction) {
    Fixture fixture(path);
    Database(path).exec("UPDATE roles SET gold=100.0,bank=100.0");
    std::vector<std::unique_ptr<richnet::Storage>> stores;
    for (int i = 0; i < 8; ++i)
        stores.push_back(std::make_unique<richnet::Storage>(path, richnet::ClientProfile::original));
    std::promise<void> start;
    const auto ready = start.get_future().share();
    std::vector<std::future<BankStatus>> results;
    for (auto& store : stores) {
        auto* writer = store.get();
        results.push_back(std::async(std::launch::async, [&, writer, ready] {
            ready.wait();
            return writer->transfer_bank("BankOwner", fixture.role_id, {direction, 25.0, limits});
        }));
    }
    start.set_value();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    int successes = 0, insufficient = 0;
    for (auto& result : results) {
        if (result.wait_until(deadline) != std::future_status::ready) {
            std::cerr << "FAIL concurrent bank transfers exceeded 10 seconds\n" << std::flush;
            std::_Exit(1);
        }
        const auto status = result.get();
        successes += status == BankStatus::success;
        insufficient += status == BankStatus::insufficient_funds;
    }
    check(successes == 4 && insufficient == 4, "concurrent handles must not overdraw source balance");
    fixture.balances(direction == BankDirection::deposit ? 0.0 : 200.0,
                     direction == BankDirection::deposit ? 200.0 : 0.0);
    check(Database(path).rows("SELECT count(*) FROM audit WHERE source='native-bank'") ==
        json::array({json::array({"8"})}), "only committed concurrent transfers create audit pairs");
}
}

int main() {
    try {
        const auto base = std::filesystem::temp_directory_path() /
            ("bank-storage-tests-" + std::to_string(GetCurrentProcessId()) + "-" +
             std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(base);
        const auto run = [&](std::string_view name, auto test) {
            test(base / (std::string(name) + ".sqlite3"));
            std::cout << "PASS " << name << '\n';
        };
        run("successful-transfers-and-persistence", successful_transfers);
        run("rejected-transfers-no-writes", rejected_transfers);
        run("ownership-and-limits", ownership_and_limits);
        run("boundaries-and-repeated-requests", boundaries_and_repetition);
        run("audit-failure-atomic-rollback", audit_failure_rolls_back);
        run("precision-loss-rejection", precision_rejection);
        run("concurrent-deposits", [](const auto& path) { concurrent_transfers(path, BankDirection::deposit); });
        run("concurrent-withdrawals", [](const auto& path) { concurrent_transfers(path, BankDirection::withdraw); });
        std::cout << "Isolated fixtures: " << base.string() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}

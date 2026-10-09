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
#include <set>
#include <string_view>
#include <vector>

namespace {
using nlohmann::json;
using richnet::ExchangeStatus;
void check(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}
class Database {
public:
    explicit Database(const std::filesystem::path& path) {
        sqlite3* raw = nullptr;
        const auto encoded = path.u8string();
        const int status = sqlite3_open(reinterpret_cast<const char*>(encoded.c_str()), &raw);
        db_.reset(raw);
        check(status == SQLITE_OK, "open exchange fixture");
        check(sqlite3_busy_timeout(db_.get(), 5000) == SQLITE_OK, "set fixture timeout");
    }
    void exec(const char* sql) {
        check(sqlite3_exec(db_.get(), sql, nullptr, nullptr, nullptr) == SQLITE_OK, "fixture SQL");
    }
    json rows(const char* sql) {
        sqlite3_stmt* raw = nullptr;
        const int prepared = sqlite3_prepare_v2(db_.get(), sql, -1, &raw, nullptr);
        std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> statement(raw, sqlite3_finalize);
        check(prepared == SQLITE_OK, "prepare fixture query");
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
        check(status == SQLITE_DONE, "finish fixture query");
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
        role_id(store.dispatch("accounts.create", {{"username", "ExchangeOwner"},
            {"password", "exchange-test"}}).at("account").at("role_id").get<std::int64_t>()) {
        Database(path).exec("UPDATE roles SET coins=5.5,gold=200.25,bank=100.5");
    }
    json role() { return store.roles_for_username("ExchangeOwner").at(0); }
    json state() {
        Database db(path);
        return json::array({role(), db.rows("SELECT * FROM audit ORDER BY id"),
            db.rows("SELECT * FROM operations ORDER BY operation_id")});
    }
    richnet::ExchangeResult exchange(double amount, std::int32_t ratio = 100) {
        return store.exchange_gold("ExchangeOwner", role_id, {amount, ratio});
    }
};
template<class Action>
void rejects(Action action, std::string_view code) {
    try { action(); }
    catch (const richnet::StorageError& error) {
        check(error.what() == code, "wrong exchange rejection code");
        return;
    }
    throw std::runtime_error("expected exchange rejection missing");
}
void failed_result(const richnet::ExchangeResult& result, ExchangeStatus expected) {
    check(result.status == expected && !result.role.has_value(), "failure status and absent snapshot");
}
void success_and_persistence(const std::filesystem::path& path) {
    json expected;
    {
        Fixture fixture(path);
        expected = fixture.role();
        expected["coins"] = 3.5;
        expected["gold"] = 400.25;
        const auto first = fixture.exchange(2);
        check(first.status == ExchangeStatus::success && first.role == expected,
              "exchange returns complete committed snapshot with fractional remainders");
        expected["coins"] = 1.5;
        expected["gold"] = 600.25;
        const auto second = fixture.exchange(2);
        check(second.status == ExchangeStatus::success && second.role == expected,
              "identical requests are independent exchanges");
        const auto audit = Database(path).rows("SELECT field,CAST(old_value AS REAL),CAST(new_value AS REAL) "
            "FROM audit WHERE source='native-exchange' ORDER BY id");
        const auto entries = json::array({json::array({"coins", "5.5", "3.5"}),
            json::array({"gold", "200.25", "400.25"}), json::array({"coins", "3.5", "1.5"}),
            json::array({"gold", "400.25", "600.25"})});
        check(audit.size() == 4, "two audit rows per exchange");
        for (const auto& row : entries)
            check(std::find(audit.begin(), audit.end(), row) != audit.end(), "audit exact asset movements");
        check(Database(path).rows("SELECT count(*) FROM audit WHERE source='native-exchange' AND "
            "username='ExchangeOwner' AND role_id=1 AND operation_id='' AND instr(reason,'100')>0") ==
            json::array({json::array({"4"})}), "audit ownership, ratio and empty operation id");
        check(Database(path).rows("SELECT count(*) FROM operations") == json::array({json::array({"0"})}),
              "exchange does not create deduplication operations");
    }
    richnet::Storage reopened(path, richnet::ClientProfile::original);
    check(reopened.roles_for_username("ExchangeOwner").at(0) == expected, "full close and reopen persists exchange");
}
void invalid_amounts(const std::filesystem::path& path) {
    Fixture fixture(path);
    const auto before = fixture.state();
    const std::array amounts{0.0, -1.0, 0.5, 1.5, std::numeric_limits<double>::quiet_NaN(),
        std::numeric_limits<double>::infinity(), -std::numeric_limits<double>::infinity(), 2147483648.0};
    for (double amount : amounts) failed_result(fixture.exchange(amount), ExchangeStatus::invalid_amount);
    failed_result(fixture.exchange(2, 1073741824), ExchangeStatus::invalid_amount);
    failed_result(fixture.exchange(6), ExchangeStatus::insufficient_funds);
    check(fixture.state() == before, "invalid and insufficient requests leave no writes");
}
void ownership_and_ratio(const std::filesystem::path& path) {
    Fixture fixture(path);
    fixture.store.dispatch("accounts.create", {{"username", "OtherOwner"}, {"password", "other-test"}});
    const auto before = fixture.state();
    for (const auto username : {"OtherOwner", "missing", "exchangeowner"})
        rejects([&] { fixture.store.exchange_gold(username, fixture.role_id, {1, 100}); }, "exchange_role_not_owned");
    rejects([&] { fixture.store.exchange_gold("ExchangeOwner", 999, {1, 100}); }, "exchange_role_not_owned");
    for (const auto ratio : {0, -1, (std::numeric_limits<std::int32_t>::min)()})
        rejects([&] { fixture.exchange(1, ratio); }, "exchange_ratio_invalid");
    check(fixture.state() == before, "ownership and ratio errors leave no writes");
}
void delta_boundaries(const std::filesystem::path& path) {
    Fixture fixture(path);
    Database(path).exec("UPDATE roles SET coins=2147483648.0,gold=0.0");
    const auto before = fixture.state();
    failed_result(fixture.exchange(2147483648.0, 1), ExchangeStatus::invalid_amount);
    check(fixture.state() == before, "above INT32_MAX delta rejected without writes");
    auto expected = fixture.role();
    expected["coins"] = 1.0;
    expected["gold"] = 2147483647.0;
    const auto maximum = fixture.exchange(2147483647.0, 1);
    check(maximum.status == ExchangeStatus::success && maximum.role == expected, "INT32_MAX delta accepted");
    expected["coins"] = 0.0;
    expected["gold"] = 4294967294.0;
    const auto maximum_ratio = fixture.exchange(1, (std::numeric_limits<std::int32_t>::max)());
    check(maximum_ratio.status == ExchangeStatus::success && maximum_ratio.role == expected,
          "maximum ratio accepted and exact source balance can be spent");
    check(fixture.role() == expected, "destination balance may exceed per-exchange delta limit");
}
void precision_rejection(const std::filesystem::path& path) {
    Fixture fixture(path);
    const std::array setups{"UPDATE roles SET coins=1.0e100,gold=100.0",
        "UPDATE roles SET coins=18014398509481984.0,gold=100.0",
        "UPDATE roles SET coins=100.0,gold=9007199254740992.0", "UPDATE roles SET coins=100.0,gold=1.0e100"};
    for (const auto setup : setups) {
        Database(path).exec(setup);
        const auto before = fixture.state();
        failed_result(fixture.exchange(3, 1), ExchangeStatus::invalid_amount);
        check(fixture.state() == before, "rounded or lost movement in either asset leaves no writes");
    }
}
void audit_rollback(const std::filesystem::path& path) {
    Fixture fixture(path);
    Database(path).exec("CREATE TRIGGER reject_second_exchange_audit BEFORE INSERT ON audit "
        "WHEN NEW.source='native-exchange' AND (SELECT count(*) FROM audit WHERE source='native-exchange')=1 "
        "BEGIN SELECT RAISE(ABORT,'injected_exchange_audit_failure'); END;");
    const auto before = fixture.state();
    bool rejected = false;
    try { fixture.exchange(1); }
    catch (const richnet::StorageError&) { rejected = true; }
    check(rejected, "second audit insertion fails exchange");
    check(fixture.state() == before, "audit failure rolls back both assets and first audit row");
    Database(path).exec("DROP TRIGGER reject_second_exchange_audit");
    check(fixture.exchange(1).status == ExchangeStatus::success, "connection usable after rollback");
}
void concurrent_exchanges(const std::filesystem::path& path) {
    Fixture fixture(path);
    Database(path).exec("UPDATE roles SET coins=5.0,gold=200.25");
    std::vector<std::unique_ptr<richnet::Storage>> stores;
    for (int i = 0; i < 8; ++i)
        stores.push_back(std::make_unique<richnet::Storage>(path, richnet::ClientProfile::original));
    std::promise<void> start;
    const auto ready = start.get_future().share();
    std::vector<std::future<richnet::ExchangeResult>> results;
    for (auto& store : stores) {
        auto* writer = store.get();
        results.push_back(std::async(std::launch::async, [&, writer, ready] {
            ready.wait();
            return writer->exchange_gold("ExchangeOwner", fixture.role_id, {1, 1});
        }));
    }
    start.set_value();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    int successes = 0, insufficient = 0;
    std::set<double> snapshots;
    for (auto& pending : results) {
        if (pending.wait_until(deadline) != std::future_status::ready) {
            std::cerr << "FAIL concurrent exchanges exceeded 10 seconds\n" << std::flush;
            std::_Exit(1);
        }
        const auto result = pending.get();
        successes += result.status == ExchangeStatus::success;
        insufficient += result.status == ExchangeStatus::insufficient_funds;
        if (result.status == ExchangeStatus::success) {
            check(result.role.has_value(), "successful contender returns snapshot");
            snapshots.insert(result.role->at("coins").get<double>());
        } else check(!result.role.has_value(), "unsuccessful contender has no snapshot");
    }
    check(successes == 5 && insufficient == 3, "eight handles compete for five M-points without overdraft");
    check(snapshots == std::set<double>{0, 1, 2, 3, 4}, "each success returns its own transaction snapshot");
    const auto role = fixture.role();
    check(role.at("coins") == 0.0 && role.at("gold") == 205.25 && role.at("bank") == 100.5,
          "concurrent final balances conserve value and bank");
    check(Database(path).rows("SELECT count(*) FROM audit WHERE source='native-exchange'") ==
        json::array({json::array({"10"})}), "only five committed exchanges append audit pairs");
}
}
int main() {
    try {
        const auto base = std::filesystem::temp_directory_path() /
            ("exchange-storage-tests-" + std::to_string(GetCurrentProcessId()) + "-" +
             std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(base);
        const auto run = [&](std::string_view name, auto test) {
            test(base / (std::string(name) + ".sqlite3"));
            std::cout << "PASS " << name << '\n';
        };
        run("success-repetition-audit-and-reopen", success_and_persistence);
        run("invalid-amounts-no-writes", invalid_amounts);
        run("ownership-and-ratio", ownership_and_ratio);
        run("gold-delta-boundaries", delta_boundaries);
        run("precision-loss-no-writes", precision_rejection);
        run("second-audit-failure-rolls-back", audit_rollback);
        run("concurrent-eight-handles-five-points", concurrent_exchanges);
        std::cout << "Isolated fixtures: " << base.string() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}

#include "lobby_runtime.hpp"
#include "auxiliary.hpp"
#include "server_lobby_adapter.hpp"
#include "original_lobby_adapter.hpp"
#include "original_blacklist.hpp"
#include "richonline_blacklist.hpp"
#include "richonline_auxiliary_store.hpp"
#include "richonline_ranking.hpp"
#include "blacklist_store.hpp"
#include "service.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <mutex>
#include <thread>

namespace richnet {
namespace {
using Json = nlohmann::json;
std::uint16_t port(const Json& value) {
    if (!value.is_number_integer() || value < 0 || value > 65535)
        throw CodecError("lobby_network_port_invalid");
    return value.get<std::uint16_t>();
}
void network_fields(const Json& value, std::initializer_list<std::string_view> allowed) {
    if (!value.is_object()) throw CodecError("original_network_object_required");
    for (const auto& [key, unused] : value.items()) {
        static_cast<void>(unused);
        if (std::find(allowed.begin(), allowed.end(), key) == allowed.end())
            throw CodecError("original_network_unknown_field");
    }
}
}

struct LobbyRuntime::Impl {
    ControlLog log;
    std::unique_ptr<ServerLobbyAdapter> adapter;
    std::unique_ptr<RichLobbyService> lobby;
    std::unique_ptr<BlacklistStore> blacklist;
    std::shared_ptr<RichonlineAuxiliaryStore> auxiliary_store;
    std::shared_ptr<RichonlineRankingStore> ranking_store;
    std::unique_ptr<AuxiliaryService> auxiliary;
    std::shared_ptr<RichonlineGameRegistry> game_registry;
    std::shared_ptr<OriginalGameHost> original_host;
    std::unique_ptr<GameService> game;
    std::thread lobby_thread, auxiliary_thread, game_thread;
    mutable std::mutex mutex;
    std::string failure;
    std::atomic_bool stopping{false};

    explicit Impl(ControlLog sink) : log(std::move(sink)) {}
    ~Impl() { stop(); }
    void failed(const std::string& service, const std::exception& error) {
        {
            const std::lock_guard lock(mutex);
            failure = service + ":" + error.what();
        }
        try { log("listener_failed", {{"service", service}, {"reason", error.what()}, {"level", "error"}}); }
        catch (...) { /* Keep the worker failure available through status even if logging failed. */ }
    }
    void stop() noexcept {
        if (stopping.exchange(true)) return;
        if (game) game->stop();
        if (auxiliary) auxiliary->stop();
        if (lobby) lobby->stop();
        if (game_thread.joinable()) game_thread.join();
        if (auxiliary_thread.joinable()) auxiliary_thread.join();
        if (lobby_thread.joinable()) lobby_thread.join();
        if (game_registry) {
            try { game_registry->shutdown(); }
            catch (const std::exception& error) {
                try { failed("game_cleanup", error); } catch (...) {}
            }
        }
        if (original_host) {
            try { original_host->shutdown(); }
            catch (const std::exception& error) { try { failed("original_game_cleanup",error); } catch (...) {} }
        }
    }
    template<class Ready> void wait_ready(Ready ready) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!ready()) {
            {
                const std::lock_guard lock(mutex);
                if (!failure.empty()) throw CodecError(failure);
            }
            if (std::chrono::steady_clock::now() >= deadline) throw CodecError("listener_start_timeout");
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
    void start_auxiliary(AuxiliaryOptions options) {
        options.lobby_port = lobby->bound_port();
        options.current_players = [this] { return lobby->authenticated_sessions(); };
        const bool needs_intro=options.intro_port.has_value();
        const bool needs_inquiry=options.inquiry_port.has_value();
        auxiliary = std::make_unique<AuxiliaryService>(options, [this](const AuxiliaryEvent& event) {
            Json details{{"service", event.service == AuxiliaryKind::http ? "http" :
                (event.service==AuxiliaryKind::intro ? "intro" : event.service==AuxiliaryKind::inquiry ? "inquiry" : "black")},
                {"connection_id", event.connection_id}, {"request_bytes", event.request_bytes},
                {"response_bytes", event.response_bytes}, {"port", event.port}};
            if (event.wire_type) details["wire_type"] = *event.wire_type;
            if (!event.reason.empty()) {
                details["reason"] = event.reason;
                if (event.event == "auxiliary_connection_closed") details["level"] = "warning";
            }
            log(std::string(event.event), details);
        });
        auxiliary_thread = std::thread([this] {
            try { auxiliary->run(); }
            catch (const std::exception& error) { failed("auxiliary", error); }
        });
        wait_ready([this,needs_intro,needs_inquiry] { return auxiliary->bound_http_port()!=0 && auxiliary->bound_black_port()!=0 &&
            (!needs_intro || auxiliary->bound_intro_port()!=0) && (!needs_inquiry || auxiliary->bound_inquiry_port()!=0); });
    }
    void start_original_game(OriginalRuntimeGame options, std::string bind_host) {
        if (!options.provider) throw CodecError("original_runtime_game_provider_missing");
        game = std::make_unique<GameService>(ServiceOptions{std::move(bind_host),options.port,ClientVersion::legacy},
            [this] {
                const std::lock_guard lock(mutex);
                return original_host ? original_host->callbacks() : GameCallbacks{};
            },[this](const std::string& message) { log("game_transport",{{"message",message}}); });
        game_thread = std::thread([this] {
            try { game->run(); }
            catch (const std::exception& error) { failed("original_game",error); }
        });
        wait_ready([this] { return game->bound_port() != 0; });
        auto host = std::make_shared<OriginalGameHost>(std::move(options.provider),
            OriginalGameEndpoint{options.advertised_address,game->bound_port()},options.admission_ttl,
            [] { return AdmissionClock::now(); },[this](const std::string& message) { log("game_transport",{{"message",message}}); });
        const std::lock_guard lock(mutex);
        original_host = std::move(host);
    }
};

LobbyRuntime::LobbyRuntime(Storage& storage, const std::filesystem::path& bootstrap, const ControlLog& log,
                           std::optional<RichonlineRuntimeGame> game, std::optional<OriginalRuntimeGame> original_game) {
    if (original_game && storage.client_profile() != ClientProfile::original)
        throw CodecError("original_game_provider_requires_original_client");
    if (!std::filesystem::exists(bootstrap)) {
        if (game) throw CodecError("richonline_game_requires_lobby_bootstrap");
        if (original_game) throw CodecError("original_game_requires_lobby_bootstrap");
        return;
    }
    std::ifstream input(bootstrap, std::ios::binary);
    if (!input) throw CodecError("bootstrap_file_open_failed");
    const auto config = Json::parse(input);
    const auto& network = config.at("network");
    ServerLobbyOptions options;
    options.host = network.at("bind_host").get<std::string>();
    options.port = port(network.at("lobby_port"));
    impl_ = std::make_unique<Impl>(log);
    auto* owner = impl_.get();
    const auto transport_log = [owner](const std::string& message) {
        owner->log("lobby_transport", {{"message", message}});
    };
    if (storage.client_profile() == ClientProfile::original) {
        if (game) throw CodecError("richonline_game_provider_requires_new_client");
        network_fields(network, {"bind_host", "lobby_port", "auxiliary"});
        const auto policy = load_original_lobby_policy(bootstrap);
        if (original_game) owner->start_original_game(std::move(*original_game),options.host);
        owner->lobby = std::make_unique<RichLobbyService>(
            LobbyOptions{options.host, options.port, local_lobby_handshake(), ClientVersion::legacy},
            make_original_lobby_factory(storage,policy,transport_log,owner->original_host),
            transport_log);
        owner->lobby_thread = std::thread([owner] {
            try { owner->lobby->run(); }
            catch (const std::exception& error) { owner->failed("lobby", error); }
        });
        owner->wait_ready([owner] { return owner->lobby->bound_port() != 0; });
        if (network.contains("auxiliary")) {
            const auto& settings = network.at("auxiliary");
            network_fields(settings, {"advertised_host", "http_port", "black_port"});
            AuxiliaryOptions aux;
            aux.bind_host = options.host;
            aux.advertised_host = settings.at("advertised_host").get<std::string>();
            aux.http_port = port(settings.at("http_port"));
            aux.black_port = port(settings.at("black_port"));
            aux.channel_id = policy.room_id;
            aux.capacity = policy.player_capacity;
            aux.lobby_type = 0;
            owner->blacklist = std::make_unique<BlacklistStore>(bootstrap.parent_path() / L"original-blacklist.sqlite3");
            aux.black_response = [owner](View request) { return original_blacklist_response(*owner->blacklist, request); };
            owner->start_auxiliary(std::move(aux));
        }
        return;
    }
    AuxiliaryOptions aux;
    aux.bind_host = options.host;
    aux.advertised_host = network.at("advertised_host").get<std::string>();
    aux.http_port = port(network.at("http_port"));
    aux.black_port = port(network.at("black_port"));
    // NEW owner+MD5(account) names a store namespace; it does not authenticate
    // a remote caller. Keep this service local until a session binding exists.
    if (aux.bind_host!="127.0.0.1" && aux.bind_host!="localhost")
        throw CodecError("richonline_blacklist_authenticated_binding_required");
    owner->blacklist=std::make_unique<BlacklistStore>(bootstrap.parent_path()/L"richonline-blacklist.sqlite3");
    aux.black_response=[owner](View request) { return richonline_blacklist_response(*owner->blacklist,request); };
    if (network.contains("intro_port")) {
        aux.intro_port=port(network.at("intro_port"));
        owner->auxiliary_store=std::make_shared<RichonlineAuxiliaryStore>(storage.database_path());
        aux.intro_response=[store=owner->auxiliary_store](View request) { return store->intro_response(request); };
    }
    if (network.contains("inquiry_port")) {
        aux.inquiry_port=port(network.at("inquiry_port"));
        owner->ranking_store=std::make_shared<RichonlineRankingStore>(storage.database_path());
        aux.inquiry_response=[store=owner->ranking_store](View request) { return store->response(request); };
    }
    const auto blobs = load_bootstrap_blobs(bootstrap);
    aux.capacity = blobs.player_capacity;
    owner->adapter = std::make_unique<ServerLobbyAdapter>(storage, blobs, log);
    if (blobs.richonline_mall_policy) {
        // Loading a real catalog is separate from the trusted client/database
        // date-mode contract. Never synthesize offers from an empty response.
        if (!config.contains("richonline_boss_game") || !config.at("richonline_boss_game").contains("client_root") ||
            !config.at("richonline_boss_game").at("client_root").is_string())
            throw CodecError("richonline_mall_resource_root_required");
        const auto name=config.at("richonline_boss_game").at("client_root").get<std::string>();
        if (name.empty() || name.find('\0')!=name.npos) throw CodecError("richonline_mall_resource_root_invalid");
        std::filesystem::path resources(std::u8string(name.begin(),name.end()));
        if (resources.is_relative()) resources=std::filesystem::absolute(bootstrap).parent_path()/resources;
        owner->adapter->set_mall_catalog(std::make_shared<const RichonlineMallCatalog>(RichonlineMallCatalog::load(resources.lexically_normal())));
        owner->log("richonline_mall_configured",{{"catalog","NEW Prop/SellProp resources"},
            {"date_mode",blobs.richonline_mall_policy->date_version==RichonlineInventoryDateVersion::original_2005 ? "original_2005" : "compat_2021_v1"},
            {"client_mode_evidence","trusted deployment configuration; no remote image attestation"},
            {"runtime_client_verified",false}});
    }
    aux.channels = blobs.channels;
    aux.channel_players = [owner](std::uint32_t channel) { return owner->adapter->channel_player_count(channel); };
    if (game) {
        if (!game->provider) throw CodecError("richonline_runtime_game_provider_missing");
        if (game->manager != 0) throw CodecError("richonline_runtime_game_manager_mismatch");
        owner->game_registry = std::make_shared<RichonlineGameRegistry>(
            [owner, provider = std::move(game->provider)](const RichonlineRoomSnapshot& room) {
                const auto bound = owner->game->bound_port();
                if (bound == 0) throw CodecError("richonline_game_listener_not_ready");
                return provider(bound, room);
            }, game->manager, game->admission_ttl);
        owner->adapter->set_game_registry(owner->game_registry);
        owner->game = std::make_unique<GameService>(ServiceOptions{options.host, game->port, ClientVersion::richonline},
            [owner] { return owner->game_registry->callbacks(); },
            [owner](const std::string& message) { owner->log("game_transport", {{"message", message}}); });
        owner->game_thread = std::thread([owner] {
            try { owner->game->run(); }
            catch (const std::exception& error) { owner->failed("game", error); }
        });
        owner->wait_ready([owner] { return owner->game->bound_port() != 0; });
    }
    owner->lobby = std::make_unique<RichLobbyService>(options.transport(),
        [owner] { return owner->adapter->callbacks(); }, transport_log);
    owner->lobby_thread = std::thread([owner] {
        try { owner->lobby->run(); }
        catch (const std::exception& error) { owner->failed("lobby", error); }
    });
    owner->wait_ready([owner] { return owner->lobby->bound_port() != 0; });
    owner->start_auxiliary(std::move(aux));
}

LobbyRuntime::~LobbyRuntime() = default;
void LobbyRuntime::stop() noexcept { if (impl_) impl_->stop(); }
Json LobbyRuntime::status() const {
    if (!impl_) return {{"lobbyConfigured", false}, {"lobbyReady", false}, {"httpReady", false}, {"blackReady", false}};
    const std::lock_guard lock(impl_->mutex);
    const bool healthy = impl_->failure.empty() && !impl_->stopping.load();
    Json result{{"lobbyConfigured", true}, {"lobbyReady", healthy && impl_->lobby->bound_port() != 0},
        {"httpReady", healthy && impl_->auxiliary && impl_->auxiliary->bound_http_port() != 0},
        {"blackReady", healthy && impl_->auxiliary && impl_->auxiliary->bound_black_port() != 0},
        {"gameListenerReady", healthy && impl_->game && impl_->game->bound_port() != 0},
        {"lobbyPort", impl_->lobby->bound_port()}, {"authenticatedSessions", impl_->lobby->authenticated_sessions()}};
    if (impl_->auxiliary) {
        result["httpPort"] = impl_->auxiliary->bound_http_port();
        result["blackPort"] = impl_->auxiliary->bound_black_port();
        result["introReady"] = healthy && impl_->auxiliary->bound_intro_port()!=0;
        result["introPort"] = impl_->auxiliary->bound_intro_port();
        result["inquiryReady"] = healthy && impl_->auxiliary->bound_inquiry_port()!=0;
        result["inquiryPort"] = impl_->auxiliary->bound_inquiry_port();
    }
    if (!impl_->failure.empty()) result["listenerFailure"] = impl_->failure;
    if (impl_->game) result["gamePort"] = impl_->game->bound_port();
    return result;
}
}

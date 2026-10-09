#pragma once
#include <atomic>
#include <cstdio>
#include <memory>
#include <utility>

namespace richnet {
// Observability must not interrupt an already committed gameplay or database action.
// Keep a fallback diagnostic independent of the failing sink, once per wrapper.
template<class Sink> Sink nonthrowing_diagnostic_log(Sink sink) {
    if (!sink) return {};
    auto reported=std::make_shared<std::atomic_bool>(false);
    return [sink=std::move(sink),reported](const auto&... arguments) noexcept {
        try { sink(arguments...); }
        catch (...) {
            if (!reported->exchange(true)) {
                std::fputs("{\"level\":\"error\",\"event\":\"diagnostic_sink_failed\",\"reason\":\"log_callback_threw\",\"gameplay_continues\":true}\n",stderr);
                std::fflush(stderr);
            }
        }
    };
}
}

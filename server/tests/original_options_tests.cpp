#include "original_options.hpp"
#include "../vendor/lzokay/lzokay.hpp"

#include <functional>
#include <iostream>
#include <limits>

namespace {
void check(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}
void rejects(const std::function<void()>& action, std::string_view code) {
    try { action(); } catch (const richnet::CodecError& error) {
        check(error.what() == code, std::string("unexpected rejection: ") + error.what());
        return;
    }
    throw std::runtime_error("expected rejection missing");
}
richnet::Bytes envelope(richnet::View compressed, std::uint32_t size, std::uint8_t key = 0x28) {
    richnet::Bytes packed{key};
    richnet::append_le(packed, size, 4);
    richnet::append_le(packed, static_cast<std::uint32_t>(compressed.size()), 4);
    packed.insert(packed.end(), compressed.begin(), compressed.end());
    for (std::size_t i = 1; i < packed.size(); ++i) packed[i] = static_cast<std::uint8_t>(packed[i] + key);
    return packed;
}
richnet::Bytes compressed(std::string_view text) {
    richnet::Bytes result(lzokay::compress_worst_size(text.size()));
    std::size_t size = 0;
    check(lzokay::compress(reinterpret_cast<const std::uint8_t*>(text.data()), text.size(),
                          result.data(), result.size(), size) == lzokay::EResult::Success,
          "fixture compression failed");
    result.resize(size);
    return result;
}
void test_kpd() {
    constexpr std::string_view plain = "[J_R]\r\nratio=17\r\n";
    const auto payload = compressed(plain);
    for (const auto key : {std::uint8_t{0}, std::uint8_t{40}, std::uint8_t{255}}) {
        const auto decoded = richnet::decode_original_kpd(envelope(payload, static_cast<std::uint32_t>(plain.size()), key));
        check(std::string_view(reinterpret_cast<const char*>(decoded.data()), decoded.size()) == plain,
              "byte offset and LZO roundtrip mismatch");
    }
    for (std::size_t size = 0; size < 9; ++size)
        rejects([&] { richnet::decode_original_kpd(richnet::Bytes(size)); }, "original_kpd_header_truncated");
    for (const auto size : {0U, 4U * 1024U * 1024U + 1U, 0xffffffffU})
        rejects([&] { richnet::decode_original_kpd(envelope(payload, size)); }, "original_kpd_lengths_invalid");
    auto truncated = envelope(payload, static_cast<std::uint32_t>(plain.size()));
    truncated.pop_back();
    rejects([&] { richnet::decode_original_kpd(truncated); }, "original_kpd_lengths_invalid");
    auto wrong_header = envelope(payload, static_cast<std::uint32_t>(plain.size()));
    for (std::size_t i = 5; i < 9; ++i) wrong_header[i] = 0x27;
    rejects([&] { richnet::decode_original_kpd(wrong_header); }, "original_kpd_lengths_invalid");
    rejects([&] { richnet::decode_original_kpd(envelope(payload, static_cast<std::uint32_t>(plain.size() + 1))); },
            "original_kpd_decoded_length_invalid");
    rejects([&] { richnet::decode_original_kpd(envelope(payload, 1)); }, "original_kpd_decompression_failed");
    for (const auto& invalid : {richnet::Bytes{}, richnet::Bytes{0, 0, 0}, richnet::Bytes{32, 0, 0},
                               richnet::Bytes{16, 0, 0}, richnet::Bytes{64, 0, 0}})
        rejects([&] { richnet::decode_original_kpd(envelope(invalid, 64)); }, "original_kpd_decompression_failed");
    auto trailing = payload;
    trailing.push_back(1);
    rejects([&] { richnet::decode_original_kpd(envelope(trailing, static_cast<std::uint32_t>(plain.size()))); },
            "original_kpd_decompression_failed");
    rejects([] { richnet::decode_original_kpd(richnet::Bytes(lzokay::compress_worst_size(4U * 1024U * 1024U) + 10U)); },
            "original_kpd_size_invalid");
}
void test_ini() {
    using richnet::parse_original_exchange_ratio;
    check(parse_original_exchange_ratio("[J_R]\nratio=1") == 1, "minimum ratio");
    check(parse_original_exchange_ratio("[j_r]\r\n RATIO : 2147483647 \r\n") == std::numeric_limits<std::int32_t>::max(), "maximum ratio");
    check(parse_original_exchange_ratio(";comment\n[other]\nratio=99\n[J_R]\nname=\xd6\xd0\xce\xc4\nratio=00017\n# comment\n//ratio=99\n") == 17,
          "GBK bytes outside ASCII fields must remain opaque");
    for (const auto text : {"[other]\nratio=10", "[J_R]\nother=10", "[DEFAULT]\nratio=10\n[J_R]\n"})
        rejects([&] { parse_original_exchange_ratio(text); }, "original_options_ratio_missing");
    for (const auto value : {"-1", "+1", "", "1.0", "one", "1x", "1 0", "10 ;inline"})
        rejects([&] { parse_original_exchange_ratio(std::string("[J_R]\nratio=") + value); }, "original_options_ratio_invalid");
    for (const auto value : {"0", "2147483648", "4294967296", "999999999999999999999999"})
        rejects([&] { parse_original_exchange_ratio(std::string("[J_R]\nratio=") + value); }, "original_options_ratio_out_of_range");
    for (const auto text : {"[J_R]\nratio=10\nratio=10", "[J_R]\nratio=10\nRATIO=11", "[J_R]\nratio=10\n[J_R]\n", "[J_R]\n[J_r]\nratio=10"})
        rejects([&] { parse_original_exchange_ratio(text); }, "original_options_ratio_ambiguous");
    rejects([&] { parse_original_exchange_ratio(""); }, "original_options_text_invalid");
    rejects([&] { parse_original_exchange_ratio(std::string_view("[J_R]\nratio=10\0", 15)); }, "original_options_text_invalid");
    rejects([&] { parse_original_exchange_ratio("[J_R\nratio=10"); }, "original_options_section_invalid");
    rejects([&] { parse_original_exchange_ratio("[J_R]\nratio"); }, "original_options_ratio_invalid");
}

void test_kpd_limits() {
    constexpr std::size_t maximum_limit = 64U * 1024U * 1024U;
    constexpr std::string_view plain = "bounded binary payload";
    const auto packet = envelope(compressed(plain), static_cast<std::uint32_t>(plain.size()));
    check(richnet::decode_original_kpd(packet, plain.size()).size() == plain.size(), "exact decoded limit must succeed");
    check(richnet::decode_original_kpd(packet, maximum_limit).size() == plain.size(), "64 MiB limit must be accepted");
    rejects([&] { richnet::decode_original_kpd(packet, plain.size() - 1); }, "original_kpd_lengths_invalid");
    for (const auto limit : {std::size_t{0}, maximum_limit + 1, std::numeric_limits<std::size_t>::max()}) {
        rejects([&] { richnet::decode_original_kpd(packet, limit); }, "original_kpd_limit_invalid");
        rejects([&] { richnet::load_original_kpd("nonexistent-options-test.kpd", limit); }, "original_kpd_limit_invalid");
    }
    const std::string large_plain(4U * 1024U * 1024U + 1U, 'x');
    const auto large_packet = envelope(compressed(large_plain), static_cast<std::uint32_t>(large_plain.size()));
    rejects([&] { richnet::decode_original_kpd(large_packet); }, "original_kpd_lengths_invalid");
    const auto large_decoded = richnet::decode_original_kpd(large_packet, maximum_limit);
    check(std::string_view(reinterpret_cast<const char*>(large_decoded.data()), large_decoded.size()) == large_plain,
          "explicit limit must allow full payload above default 4 MiB");
    for (const auto size : {std::uint32_t{0}, static_cast<std::uint32_t>(maximum_limit + 1), 0xffffffffU})
        rejects([&] { richnet::decode_original_kpd(envelope(compressed(plain), size), maximum_limit); }, "original_kpd_lengths_invalid");
    rejects([&] { richnet::decode_original_kpd(envelope(richnet::Bytes{0, 0, 0}, 64), maximum_limit); },
            "original_kpd_decompression_failed");
}

void test_price_base() {
    using richnet::parse_original_price_base;
    check(parse_original_price_base("[OTHER]\npriceBase=1") == 1, "minimum price base");
    check(parse_original_price_base("[other]\r\n PRICEBASE : 2147483647\r\n") == std::numeric_limits<std::int32_t>::max(),
          "maximum price base");
    check(parse_original_price_base("[J_R]\npriceBase=99\n[OTHER]\n//priceBase=9\npriceBase=00017\n") == 17,
          "price base uses own section and ignores comments");
    for (const auto text : {"[J_R]\npriceBase=10", "[OTHER]\nratio=10"})
        rejects([&] { parse_original_price_base(text); }, "original_options_price_base_missing");
    for (const auto value : {"-1", "+1", "", "1.5", "ten", "10 // inline"})
        rejects([&] { parse_original_price_base(std::string("[OTHER]\npriceBase=") + value); }, "original_options_price_base_invalid");
    for (const auto value : {"0", "2147483648", "4294967296", "999999999999999999999"})
        rejects([&] { parse_original_price_base(std::string("[OTHER]\npriceBase=") + value); }, "original_options_price_base_out_of_range");
    for (const auto text : {"[OTHER]\npriceBase=10\npriceBase=10", "[OTHER]\npriceBase=10\nPRICEBASE=11", "[OTHER]\npriceBase=10\n[other]\n"})
        rejects([&] { parse_original_price_base(text); }, "original_options_price_base_ambiguous");
    rejects([&] { parse_original_price_base("[OTHER]\npriceBase"); }, "original_options_price_base_invalid");
}
}

int main() {
    try {
        test_kpd();
        test_kpd_limits();
        test_ini();
        test_price_base();
        constexpr std::u8string_view source_path = RICHONLINE_LEGACY_RESOURCE_ROOT;
        const auto root = std::filesystem::path(std::u8string(source_path.begin(), source_path.end()));
        check(richnet::load_original_exchange_ratio(root / "Data" / "Option.kpd") == 10, "actual Data/Option.kpd ratio must be 10");
        check(richnet::load_original_price_base(root / "Data" / "Option.kpd") == 10, "actual Data/Option.kpd priceBase must be 10");
        const auto options = richnet::load_original_kpd(root / "Data" / "Option.kpd");
        check(richnet::parse_original_price_base({reinterpret_cast<const char*>(options.data()), options.size()}) == 10,
              "reusable file decoder must deliver actual Option text");
        rejects([&] { richnet::load_original_exchange_ratio(root / "nonexistent-options-test.kpd"); }, "original_options_open_failed");
        std::cout << "PASS original Option.kpd ratio=10 and priceBase=10, LZO/offset decode, configurable bounds, corruption, strict INI and ambiguous values.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}

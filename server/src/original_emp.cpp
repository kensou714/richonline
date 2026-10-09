#include "original_map.hpp"
#include "original_options.hpp"
#include <algorithm>
#include <bit>
#include <fstream>

namespace richnet {
namespace {
constexpr std::size_t decoded_limit = 64U*1024U*1024U;
constexpr std::size_t file_limit = 2U*decoded_limit;
std::uint32_t word(View data, std::size_t offset) {
    if (offset > data.size() || data.size()-offset < 4) throw CodecError("original_emp_truncated");
    return read_le(data.subspan(offset,4));
}
void advance(std::size_t& cursor, std::uint64_t count, std::uint64_t stride, std::size_t size) {
    if (cursor > size || count > (size-cursor)/stride) throw CodecError("original_emp_array_truncated");
    cursor += static_cast<std::size_t>(count*stride);
}
}
OriginalEmp decode_original_emp(View file) {
    if (file.size() > file_limit) throw CodecError("original_emp_file_too_large");
    const auto version = word(file,16);
    if (version < 1 || version > 3) throw CodecError("original_emp_version_unsupported");
    const std::size_t metadata = 3U + (version >= 2 ? 2U : 0U) + (version >= 3 ? 1U : 0U);
    const auto block = 23288U + metadata*4U + 120U;
    const auto width = word(file,23288U+(metadata-2U)*4U);
    const auto height = word(file,23288U+(metadata-1U)*4U);
    const auto cells = static_cast<std::uint64_t>(width)*height;
    if (width == 0 || height == 0 || cells > 32768) throw CodecError("original_emp_dimensions_invalid");
    if (block > file.size()) throw CodecError("original_emp_truncated");
    auto payload = decode_original_kpd(file.subspan(block),decoded_limit);
    const auto background_width = std::bit_cast<std::int32_t>(word(payload,8));
    const auto background_height = std::bit_cast<std::int32_t>(word(payload,12));
    if (background_width <= 0 || background_height <= 0) throw CodecError("original_emp_background_invalid");
    std::size_t cursor = 16;
    advance(cursor,static_cast<std::uint64_t>(background_width)*static_cast<std::uint64_t>(background_height),4,payload.size());
    const auto terrain = cursor;
    advance(cursor,cells,64,payload.size());
    const auto decorations = word(payload,cursor);
    advance(cursor,1,4,payload.size());
    advance(cursor,decorations,36,payload.size());
    const auto types = cursor;
    advance(cursor,cells,4,payload.size());
    const auto properties = cursor;
    advance(cursor,cells,88,payload.size());
    OriginalEmp result{version,width,height,{},Bytes(file.begin(),file.begin()+static_cast<std::ptrdiff_t>(block)),
        std::move(payload),terrain,types,properties,cursor};
    std::copy_n(file.begin(),16,result.signature.begin());
    return result;
}
OriginalEmp load_original_emp(const std::filesystem::path& path) {
    std::ifstream input(path.c_str(),std::ios::binary|std::ios::ate);
    if (!input) throw CodecError("original_emp_open_failed");
    const auto size = input.tellg();
    if (size < 0 || static_cast<std::uintmax_t>(size) > file_limit) throw CodecError("original_emp_file_too_large");
    Bytes file(static_cast<std::size_t>(size));
    input.seekg(0);
    if (!file.empty() && !input.read(reinterpret_cast<char*>(file.data()),static_cast<std::streamsize>(file.size())))
        throw CodecError("original_emp_read_failed");
    if (input.peek() != std::char_traits<char>::eof()) throw CodecError("original_emp_read_failed");
    return decode_original_emp(file);
}
}

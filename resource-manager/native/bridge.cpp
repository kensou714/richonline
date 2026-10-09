#include "../../server/vendor/lzokay/lzokay.hpp"
extern "C" __declspec(dllexport) int resource_decompress(const unsigned char* src, size_t length, unsigned char* dst, size_t capacity) {
    size_t actual=0;
    auto result=lzokay::decompress(src,length,dst,capacity,actual);
    return result==lzokay::EResult::Success && actual==capacity ? 0 : -1;
}
extern "C" __declspec(dllexport) int resource_compress(const unsigned char* src, size_t length, unsigned char* dst, size_t capacity, size_t* actual) {
    try { return static_cast<int>(lzokay::compress(src,length,dst,capacity,*actual)); }
    catch (...) { return -1; }
}

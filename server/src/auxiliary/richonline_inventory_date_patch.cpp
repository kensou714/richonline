#include "richonline_inventory_date_patch.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <array>

namespace richnet {
namespace {
struct Algorithm {
    BCRYPT_ALG_HANDLE handle{};
    Algorithm(){if(BCryptOpenAlgorithmProvider(&handle,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0)throw CodecError("date_patch_hash_provider_failed");}
    ~Algorithm(){if(handle)BCryptCloseAlgorithmProvider(handle,0);}
};
struct Hash {
    BCRYPT_HASH_HANDLE handle{};
    ~Hash(){if(handle)BCryptDestroyHash(handle);}
};
struct Site { std::size_t offset;std::array<std::uint8_t,6> before,after;std::size_t size; };
constexpr std::array<Site,3> sites{{
    {0x145d54,{0x05,0xd5,0x07,0,0,0},{0x05,0xe5,0x07,0,0,0},5},
    {0x146a79,{0x05,0xd5,0x07,0,0,0},{0x05,0xe5,0x07,0,0,0},5},
    {0x14d2f5,{0x81,0xc2,0xd5,0x07,0,0},{0x81,0xc2,0xe5,0x07,0,0},6}
}};
constexpr std::size_t maximum=64U*1024U*1024U;
bool matches(View image,bool patched) {
    for(const auto& site:sites) {
        if(image.size()<site.offset+site.size)return false;
        const auto& bytes=patched?site.after:site.before;
        if(!std::equal(bytes.begin(),bytes.begin()+static_cast<std::ptrdiff_t>(site.size),image.begin()+static_cast<std::ptrdiff_t>(site.offset)))return false;
    }
    return true;
}
}
std::string richonline_date_image_sha256(View image) {
    if(image.empty()||image.size()>maximum)throw CodecError("date_patch_image_size_invalid");
    Algorithm algorithm;DWORD object_size=0,returned=0;
    if(BCryptGetProperty(algorithm.handle,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&object_size),sizeof(object_size),&returned,0)<0||returned!=sizeof(object_size))
        throw CodecError("date_patch_hash_property_failed");
    Bytes object(object_size);Hash hash;
    if(BCryptCreateHash(algorithm.handle,&hash.handle,object.data(),object_size,nullptr,0,0)<0||
        BCryptHashData(hash.handle,const_cast<PUCHAR>(image.data()),static_cast<ULONG>(image.size()),0)<0)
        throw CodecError("date_patch_hash_failed");
    std::array<std::uint8_t,32> digest{};
    if(BCryptFinishHash(hash.handle,digest.data(),static_cast<ULONG>(digest.size()),0)<0)throw CodecError("date_patch_hash_finish_failed");
    constexpr char digits[]="0123456789ABCDEF";std::string result;result.reserve(64);
    for(const auto value:digest){result.push_back(digits[value>>4U]);result.push_back(digits[value&15U]);}return result;
}
Bytes richonline_date_compatibility_image(View original) {
    if(richonline_date_image_sha256(original)!=richonline_date_original_sha256)throw CodecError("date_patch_original_hash_mismatch");
    if(!matches(original,false))throw CodecError("date_patch_original_instruction_mismatch");
    Bytes result(original.begin(),original.end());
    for(const auto& site:sites)std::copy_n(site.after.begin(),site.size,result.begin()+static_cast<std::ptrdiff_t>(site.offset));
    return result;
}
bool richonline_date_compatibility_image_valid(View patched) {
    if(patched.empty()||patched.size()>maximum||!matches(patched,true))return false;
    Bytes original(patched.begin(),patched.end());
    for(const auto& site:sites)std::copy_n(site.before.begin(),site.size,original.begin()+static_cast<std::ptrdiff_t>(site.offset));
    return richonline_date_image_sha256(original)==richonline_date_original_sha256;
}
}

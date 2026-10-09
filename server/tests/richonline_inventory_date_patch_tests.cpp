#include "richonline_inventory_date_patch.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
}
int main(int argc,char** argv){try{
    check(!richonline_date_compatibility_image_valid(Bytes(100)),"short arbitrary image accepted");
    if(argc!=2)throw CodecError("test requires original NEW executable path");
    std::ifstream input(std::filesystem::path(argv[1]),std::ios::binary|std::ios::ate);check(static_cast<bool>(input),"open original");
    const auto size=input.tellg();check(size>0&&size<64*1024*1024,"image size");Bytes original(static_cast<std::size_t>(size));input.seekg(0);
    check(static_cast<bool>(input.read(reinterpret_cast<char*>(original.data()),static_cast<std::streamsize>(original.size()))),"read original");
    const auto patched=richonline_date_compatibility_image(original);check(richonline_date_compatibility_image_valid(patched),"generated image not verified");
    std::vector<std::size_t> changed;for(std::size_t index=0;index<original.size();++index)if(original[index]!=patched[index])changed.push_back(index);
    check(changed==std::vector<std::size_t>{0x145d55,0x146a7a,0x14d2f7},"unrelated bytes changed");
    auto corrupt=patched;corrupt[0]^=1;check(!richonline_date_compatibility_image_valid(corrupt),"unrelated modified executable accepted");
    corrupt=original;corrupt[0]^=1;
    try{richonline_date_compatibility_image(corrupt);throw std::runtime_error("wrong original accepted");}catch(const CodecError& error){check(std::string_view(error.what())=="date_patch_original_hash_mismatch","hash guard reason");}
    std::cout<<"PASS SHA256-bound NEW compatibility copy, exactly3 epoch bytes, original/tamper refusal; copy_sha256="<<richonline_date_image_sha256(patched)<<'\n';return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}

#include "richonline_inventory_date.hpp"
#include "richonline_inventory_date_patch.hpp"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

namespace {
using namespace richnet;
Bytes read_image(const std::filesystem::path& path) {
    std::ifstream input(path,std::ios::binary|std::ios::ate);
    if(!input)throw CodecError("date_patch_input_open_failed");const auto size=input.tellg();
    if(size<=0||size>64*1024*1024)throw CodecError("date_patch_image_size_invalid");
    Bytes bytes(static_cast<std::size_t>(size));input.seekg(0);
    if(!input.read(reinterpret_cast<char*>(bytes.data()),static_cast<std::streamsize>(bytes.size())))throw CodecError("date_patch_input_read_failed");return bytes;
}
void create_new(const std::filesystem::path& path,View bytes) {
    const auto handle=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(handle==INVALID_HANDLE_VALUE)throw CodecError("date_patch_output_exists_or_open_failed");
    DWORD written=0;const auto success=WriteFile(handle,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr)&&written==bytes.size()&&FlushFileBuffers(handle);
    CloseHandle(handle);
    if(!success){std::error_code error;std::filesystem::remove(path,error);throw CodecError("date_patch_output_write_failed");}
}
std::string utf8(const std::filesystem::path& path){const auto value=path.u8string();return {reinterpret_cast<const char*>(value.data()),value.size()};}
}
int wmain(int argc,wchar_t** argv){try{
    if(argc==3&&std::wstring_view(argv[1])==L"verify") {
        const auto image=read_image(argv[2]);
        if(!richonline_date_compatibility_image_valid(image))throw CodecError("date_patch_copy_verification_failed");
        std::cout<<nlohmann::json{{"compatibility_id",richonline_inventory_compatibility_id},{"verified",true},{"sha256",richonline_date_image_sha256(image)}}.dump()<<'\n';return 0;
    }
    if(argc!=4||std::wstring_view(argv[1])!=L"apply")throw CodecError("usage: richonline_inventory_date_patch apply ORIGINAL NEW_COPY | verify COPY");
    const auto source=std::filesystem::absolute(argv[2]).lexically_normal(),target=std::filesystem::absolute(argv[3]).lexically_normal();
    if(source==target||std::filesystem::exists(target))throw CodecError("date_patch_output_must_be_new_copy");
    const auto manifest_path=std::filesystem::path(target.wstring()+L".datecompat.json");
    if(std::filesystem::exists(manifest_path))throw CodecError("date_patch_manifest_exists");
    const auto original=read_image(source),patched=richonline_date_compatibility_image(original);
    if(!richonline_date_compatibility_image_valid(patched))throw CodecError("date_patch_copy_verification_failed");
    const nlohmann::json manifest{{"compatibility_id",richonline_inventory_compatibility_id},{"source",utf8(source)},{"copy",utf8(target)},
        {"source_sha256",richonline_date_image_sha256(original)},{"copy_sha256",richonline_date_image_sha256(patched)},
        {"inventory_date_epoch",2021},{"display_year_range",{2021,2036}},{"changed_bytes",3},{"file_offsets",{0x145d55,0x146a7a,0x14d2f7}},
        {"database_migrated",false},{"original_modified",false}};
    const auto text=manifest.dump(2)+"\n";const Bytes manifest_bytes(text.begin(),text.end());
    create_new(target,patched);
    try {create_new(manifest_path,manifest_bytes);}catch(...){std::error_code error;std::filesystem::remove(target,error);throw;}
    std::cout<<manifest.dump()<<'\n';return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}

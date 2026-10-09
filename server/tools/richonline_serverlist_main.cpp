#include "richonline_serverlist.hpp"
#include "server_lobby_adapter.hpp"
#include <windows.h>
#include <fstream>
#include <iostream>

// Produces an unused output path. Deployment and backups belong to the
// launcher/operator; this tool never overwrites the client resource.
int wmain(int argc,wchar_t** argv){try{
    if(argc!=4){std::cerr<<"usage: RichOnline.Serverlist bootstrap.json existing-Serverlist.kpd new-output.kpd\n";return 2;}
    const auto config=richnet::load_bootstrap_blobs(argv[1]);
    if(!config.social_server_id)throw richnet::CodecError("serverlist_social_server_id_required");
    std::ifstream input(std::filesystem::path(argv[2]),std::ios::binary|std::ios::ate);
    if(!input||input.tellg()<9||input.tellg()>131072)throw richnet::CodecError("serverlist_source_read_failed");
    richnet::Bytes source(static_cast<std::size_t>(input.tellg()));input.seekg(0);
    if(!input.read(reinterpret_cast<char*>(source.data()),static_cast<std::streamsize>(source.size())))throw richnet::CodecError("serverlist_source_read_failed");
    const auto original=richnet::decode_richonline_serverlist(source);
    const auto bytes=richnet::encode_richonline_serverlist(config.channels,*config.social_server_id,source.front());
    const auto output=CreateFileW(argv[3],GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(output==INVALID_HANDLE_VALUE)throw richnet::CodecError("serverlist_output_exists_or_unavailable");
    DWORD written=0;const bool success=WriteFile(output,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr)!=0&&written==bytes.size();
    const bool flushed=FlushFileBuffers(output)!=0;CloseHandle(output);
    if(!success||!flushed)throw richnet::CodecError("serverlist_output_write_failed");
    std::cout<<"Generated verified Serverlist.kpd: "<<config.channels.size()<<" actual channel labels; original resource "<<original.size()<<" labels preserved on disk.\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}

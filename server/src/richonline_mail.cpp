#include "richonline_mail.hpp"
#include <algorithm>
#include <bit>
#include <windows.h>

namespace richnet {
namespace {
void length(View payload,std::size_t expected){if(payload.size()!=expected)throw CodecError("richonline_mail_length_invalid");}
std::uint32_t word(View data,std::size_t offset){return read_le(data.subspan(offset,4));}
template<std::size_t N>std::array<std::uint8_t,N> field(View data,std::size_t offset){std::array<std::uint8_t,N> value;std::copy_n(data.subspan(offset,N).begin(),N,value.begin());return value;}
Bytes text(View value){const auto end=std::find(value.begin(),value.end(),0);if(end==value.end())throw CodecError("richonline_mail_string_unterminated");return {value.begin(),end};}
RichonlineMailKey key(View data,std::size_t offset){return {word(data,offset),word(data,offset+4)};}
RichonlineMailActor actor(View data,std::size_t offset){return {word(data,offset),field<32>(data,offset+4),std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(read_le(data.subspan(offset+36,2)))),field<2>(data,offset+38)};}
template<std::size_t N>void append(Bytes& data,const std::array<std::uint8_t,N>& value){data.insert(data.end(),value.begin(),value.end());}
void append_actor(Bytes& data,const RichonlineMailActor& value){append_le(data,value.opaque_actor_word,4);append(data,value.name);append_le(data,std::bit_cast<std::uint16_t>(value.opaque_actor_short),2);append(data,value.opaque_padding);}
}
RichonlineMailSend46 decode_richonline_mail_send46(View payload){length(payload,348);return {field<348>(payload,0),text(payload.subspan(48,36)),text(payload.subspan(84,56)),word(payload,140),text(payload.subspan(144,204))};}
void validate_richonline_mail_send46(const RichonlineMailSend46& request){
    if(request.recipient.empty() || request.recipient.size()>31 || request.subject.size()>20 || request.body.size()>200)
        throw CodecError("richonline_mail_send_text_capacity");
    for(const auto* value:{&request.recipient,&request.subject,&request.body}){
        if(std::find(value->begin(),value->end(),0)!=value->end())throw CodecError("richonline_mail_send_embedded_nul");
        if(!value->empty() && MultiByteToWideChar(950,MB_ERR_INVALID_CHARS,reinterpret_cast<const char*>(value->data()),static_cast<int>(value->size()),nullptr,0)==0)
            throw CodecError("richonline_mail_send_cp950_invalid");
    }
}
RichonlineMailClaim48 decode_richonline_mail_claim48(View payload){length(payload,12);return {key(payload,0),word(payload,8)};}
RichonlineMailKey decode_richonline_mail_delete49(View payload){length(payload,8);return key(payload,0);}
RichonlineMailRead56 decode_richonline_mail_read56(View payload){length(payload,16);if(word(payload,0)!=1 || word(payload,12)!=1)throw CodecError("richonline_mail_read_selector_invalid");return {key(payload,4)};}
RichonlineMailRecord88 decode_richonline_mail_record88(View payload){
    length(payload,348);RichonlineMailRecord88 result{word(payload,0),actor(payload,4),actor(payload,44),field<21>(payload,84),field<12>(payload,105),field<11>(payload,117),key(payload,128),word(payload,136),word(payload,140),field<204>(payload,144)};
    for(const auto value:{View(result.sender.name),View(result.recipient.name),View(result.subject),View(result.date_text),View(result.time_text),View(result.body)})(void)text(value);
    // NEW6AEBE0 copies into a 332-byte UI row: time+113, body+123,
    // attachment+324. Wire padding is not extra string capacity.
    if(text(result.body).size()>200 || text(result.time_text).size()>9)
        throw CodecError("richonline_mail_ui_text_capacity");
    return result;
}
Frame encode_richonline_mail_record88(const RichonlineMailRecord88& record){
    Bytes data;data.reserve(348);append_le(data,record.opaque_kind,4);append_actor(data,record.sender);append_actor(data,record.recipient);
    append(data,record.subject);append(data,record.date_text);append(data,record.time_text);append_le(data,record.key.high,4);append_le(data,record.key.low,4);
    append_le(data,record.read_word,4);append_le(data,record.attachment_token,4);append(data,record.body);(void)decode_richonline_mail_record88(data);return {88,std::move(data)};
}
Frame encode_richonline_mail_deleted91(RichonlineMailKey key){Bytes data;append_le(data,key.high,4);append_le(data,key.low,4);return {91,std::move(data)};}
Frame encode_richonline_mail_sent92(std::uint32_t transferred_item){
    // 86D2C0 tests signed > 0 before looking up and deleting the owned object.
    if(transferred_item>0x7fffffffU)throw CodecError("richonline_mail_sent_item_signed_range");
    Bytes data;append_le(data,transferred_item,4);return {92,std::move(data)};
}
Frame encode_richonline_mail_claimed93(RichonlineMailKey key,std::uint32_t item){
    if(item==0)throw CodecError("richonline_mail_claim_item_invalid");Bytes data;append_le(data,item,4);append_le(data,key.high,4);append_le(data,key.low,4);return {93,std::move(data)};
}
}

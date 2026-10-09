#pragma once

#include "codec.hpp"

namespace richnet {
class BlacklistStore;
// NEW auxiliary request, one complete CRLF-framed packet. Empty output is the
// confirmed type4 no-reply operation. Type3 returns unsupported status -1.
// The store must be NEW-only (richonline-blacklist.sqlite3). Its owner/digest
// key is role-name plus MD5(account), NOT proof of authentication. Expose this
// adapter only on loopback until the host supplies authenticated-session binding.
Bytes richonline_blacklist_response(BlacklistStore& store, View request);
}

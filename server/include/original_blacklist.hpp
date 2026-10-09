#pragma once

#include "codec.hpp"

namespace richnet {
class BlacklistStore;
// One complete original auxiliary request; output can contain multiple list records.
Bytes original_blacklist_response(BlacklistStore& store, View request);
}

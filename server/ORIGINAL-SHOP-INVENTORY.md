# Original inventory and board shop

This C++20 module replaces the corresponding Python reference logic for the
root RnClient.exe. It reads original KPD files directly. The static evidence
is `protocol-analysis/ORIGINAL-SHOP-INVENTORY-RECHECK-20261009.md`.
It is a battle-strategy building block; original production room handoff,
complete landing/combat policy and actual-client acceptance remain unfinished.
`gameReady` remains false.

## Resources and slot fields

`original_card_resources` decodes Data/Prop.kpd and Data/CombCard.kpd through
the native KPD reader. All decoded bytes and source fields are retained.
Values such as Chinese names remain original GBK bytes, not mislabeled UTF-8.
The actual files contain100 CARD records and12 ordered recipes.

Prop key names and `true` checks are case-sensitive. `enable` consumes its
first comma component; `saleG` consumes the whole value. Missing values remain
visible in the resource model; shop policy applies the constructor-proven
defaults enable=false, saleG=false, priceG=0 and fold=1. Negative prices or
nonpositive/oversized shop counts are rejected at the shop boundary. The
resource parser retains signed32 prices/fold. IDs and active ingredient counts
use validated ranges rather than reproducing unsafe atoi truncation.

Six-byte slots contain i16 id, i16 count and two individually preserved bytes.
The client constructor initializes empty slots to `FF FF 00 00 00 FF`.
The last two bytes' business meanings remain unresolved. Add, remove, sale,
discard and synthesis alter only id/count. No generic zero padding is added.
Main inventory has8 slots; shop has12.

Adding inserts in the first empty slot; matching IDs do not merge. Removal
subtracts quantity, clearing id/count at zero. Sale/discard remove the entire
slot. Full insertion returns unchanged inventory without running synthesis.
Synthesis follows each enabled recipe once in source order and requires its
output ID in the map pair table. Each ingredient matches a number of slots,
not the sum of stack counts. Matching does not exclude previously marked
slots between ingredient rows, preserving the client's repeated-source behavior.
The output occupies the lowest consumed slot with count1, preserving that
slot's tail. Later recipes may consume earlier outputs; earlier ones are not
retried. Missing enable/dest and unsafe zero-source recipes are rejected.

## Shop authority and accounting

`original_shop_catalog` selects enabled saleG cards present in the actual map
pair table, reads each priceG/fold, and keeps all CARD prices for selling.
The current stock policy samples eligible cards without replacement through
an injected RNG. This is an explicit local policy, not recovered historical
server randomness. It does not label either map weighted pool as a universal
reward pool. Stock count comes from Prop fold and stock tails use the proven
constructor values.

`OriginalShop` owns one visit's inventory, board tickets, account reserve,
stock, fixed deadline and refresh count. Its caller must authenticate the
actor, ensure other world operations cannot mutate that inventory concurrently,
and carry the returned authoritative wallet back into battle state. Setup
requires the instance, context, owner, opened time and an optional validated
refresh charge. Pass no price when its effective value is not known.

Wire behavior:

| Request | Success response | State change |
|---|---|---|
|48,index0..11|4031,index|Add stock id/count, synthesize, deduct priceG once, clear offer|
|48,index-1|4031,-1|Close once; client continues landing phase2|
|49,slot0..7|4032,slot|Remove whole slot, credit priceG arithmetic half once|
|50,slot0..7|4033,slot,owner|Clear whole slot, no income or turn advance|
|53|4030,refresh1|Replace stock, debit account reserve, retain original deadline|

48/49/50 are exactly6 bytes, including one preserved unwritten tail byte;
53 is exactly4.4030 includes all12×6 records plus the refresh flag (77 bytes).
New visits use flag0. Refresh uses flag1 and is limited to5 per visit. A refresh
never extends the10-second visit. Buy/sell count does not multiply the charge
or refund. Tickets are distinct from the signed32 client account reserve.
`OriginalShopResult.account_charge` explicitly reports a refresh debit; the
future production strategy must commit/synchronize it with account storage
before releasing the response. This library alone does not perform a durable
account transaction and its tests do not claim that integration.

The refresh resource is GValue index260, loaded indirectly by70BDF0 into the
client global at994088. Native `original_game_values` preserves the complete
file and rejects missing required entries. The actual bundled GValue.kpd has
38 entries0..37 and no260. That absence does not prove free refresh or an
effective runtime cost. Native53 without a validated price closes with an
explicit `original_shop_refresh_price_unrecovered` reason and no debit. Paid
refresh tests use a visibly synthetic configured price5, not a claimed live
client fee.

No buy/sell failure opcode was recovered. On insufficient tickets, full bag,
empty offer/slot or unsupported refresh, this implementation closes with
4031(-1) and returns a structured rejection string. This is a bounded local
policy, not the historical server's proven error response. It avoids sending
4030(flag1) as a rejection refresh, which would wrongly charge the account.
The caller must log the rejection alongside connection/context and continue
the actual landing pipeline, including a pending fork when applicable.

## Idle deadlines and late exits

GameCallbacks and OriginalGamePlan have optional poll callbacks. GameService
handles all readable peers first, then polls surviving admitted peers every
select cycle (up to100ms idle delay). Original callbacks poll only after map
readiness and use the same encoding/Gmsv/context checks as request replies.
Exceptions close only that peer; feed/poll/EOF/stop/destruction clean up once.

An owning strategy calls shop.poll(monotonic_now), publishes any4031(-1),
resolves the landing/fork and advances only after that decision finishes.
The deadline is enforced even if the UI countdown disappears without sending48.
Request handling also checks the deadline before applying a transaction.

OriginalGamePlan.closed_shop_context may return a proved closed human-shop
context. Only exact-length48 with index-1 and that context is ignored before
ordinary context validation. It sends no duplicate close and advances no turn.
Old buys/sales and malformed exits retain normal rejection. The strategy must
clear this record when a new human shop begins, must not replace it when a BOSS
auto-closes, and must not expose a currently active shop context as closed.
The field is per admitted session, not a global stale-action bypass.

## Card rewards and remaining landing work

`grant_original_card` models4029 insertion of one card and synthesis. It still
emits4029 when the human bag is full because the client queues landing phase2
even after failed insertion. The result explicitly reports insertion success
and combination changes. The owning strategy decides whether a grant applies
to the current actor; BOSS mode skips BOSS reward tiles. It also supplies the
selected card; no unverified map-pool selection or fixed terrain-card mapping
is guessed by this module.

Existing original disassembly proves ticket tiles5/6/7 auto-add80/50/30 in the
client. The server must mirror those once without another additive response.
The caller must also apply control-state and BOSS guards before normal rewards.
Properties, gods, card use, mines/bombs, chance, settlement and full multiplayer
barriers remain battle-policy work; this module does not silently skip them.

## Verification evidence

Wire tests use literal bytes and nonzero tail fields. Inventory tests distinguish
slot matching from quantity matching, prove recipe-order effects and compare
actual resources. Shop tests cover purchase/sale/discard, duplicate offers,
full bag, insufficient balances, refresh limits, deadline boundaries, exact
account charge, actual KPD/fold, synthesis and full-bag4029 continuation.

The encrypted TCP test uses original BS_1_1 movement179→178, opens the shop,
buys/sells, advances an injected clock and receives4031(-1) with no client
request, chooses direction2, then moves178→162. It tests both same-context and
old-context delayed exits, rejects old-context buys/sales, and keeps the other
session alive. Separate poll tests cover map gates, output validation, idle
push, failure isolation and cleanup. Startup unknowns, offers/price and
completion of non-shop events in these fixtures are synthetic test policy;
this is not an original-client graphical playthrough.

# Vault composition contract

One Vault has actual `ckmg::Keys<KeyStore<B>, ...>` and one shared authenticated
`cwst::Store<B>`. All domain candidates use the same checkpoint version observed
before preparation. `Store::is_scope` prevents wrong-community loading even for
an empty store. No cached credential, lineage or wallet state is copied here.

`stage_keys(Batch)` reserves one write. Keep its cancellation guard alive while
calling Keys' mutation commit or acknowledgement. The adapter consumes the batch
only at `SecureStore::compare_exchange`, compares the exact previous key ciphertext
digest, and commits that replacement plus companion changes/outbox in one durable
cwst transaction. Keys' sealed payload already contains its pending receipt.
Without an armed batch, writes refuse. A consumed batch remains reserved until
the guard drops. A cancelled or uncertain commit cannot be reported as committed;
reopen and reconcile the actual operation/outbox. No automatic retry regenerates
ciphertext, a signature, a reservation or a proof. Dependent owners adopt their
candidates only after this durable result, through their own receipt interfaces.

Mutation `keys` ownership is reserved to the adapter. Domain owner payloads stay
opaque. Current G3 authority is injected into Keys and checked by Keys itself;
this crate supplies no permissive implementation. Production authority is blocked
on the identity owner's live passkey/membership adapter. Tests using a signed
fixture lineage demonstrate composition mechanics only, never live authority.

Records is an independent trusted port while cdht's owner completes its actual
protocol adapter. Present means an authenticated encrypted record; KnownAbsent
requires that owner's protocol evidence. Timeouts and unverifiable or incomplete
knowledge are Unavailable. Vault never infers absence, calls create on restore,
or interprets a lookup result as permission to mint a replacement identity. This port
performs lookup only; installing record data needs the owner's authenticated
merge/lineage evidence and the shared checkpoint transaction. Whole active-member
data restore remains unaccepted until real cdht and holder adapters run together.

Wallet remains a borrowed owner capability supplied by accounting. There is no
substitute proof success path. Keys derives the global passport holder seed; Wallet holds the passport and
operates Pseudonyms' holder side. These owner integrations are pending.

Every enrolled passkey is equal. Keys must retain a random common identity root
as separate authenticated wrapped copies under each passkey in member DHT records.
Devices refresh those records during use; the operator keeps no copy. Loss of all
local and DHT copies after long absence can lose identity and data equally for
every passkey. No first passkey retains privileged recordless recovery. This rule
does not define a new wrapping format, discovery scheme or retention guarantee;
those owner ports must be implemented and reviewed before restore is accepted.
The current deterministic Keys implementation is not evidence of that contract.
Vault only composes its eventual owner checkpoints and outputs atomically. No local
HTTP/WebAuthn/network code, raw root export, operator backup or duplicated domain
state is introduced. `lock` wipes Keys and shared decrypted Storage immediately;
existing shared container references then receive Locked from Storage.

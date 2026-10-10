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

Records is an independent trusted port. `PasskeyRecords` forwards the original
`cdht::runtime::Record` without another record engine or replica cache.
Present means an authenticated encrypted record; KnownAbsent
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
A local Keys checkpoint alone is not evidence of that end-to-end contract.
Vault composes the original owner checkpoints and outputs atomically. No local
HTTP/WebAuthn/network code, raw root export, operator backup or duplicated domain
state is introduced. `lock` wipes Keys and shared decrypted Storage immediately;
existing shared container references then receive Locked from Storage.

`open_existing` is a consume-only local opening path. It never calls Store create,
Keys create_scope, Records lookup or a Wallet constructor. The original UnlockSecret
is consumed into PrfOutput once; the borrowed opaque PRF feeds original store_cipher
and Keys.unlock without cloning/export. A current Keys.lineage/Authority check is
mandatory before the Vault returns. On error or cancellation, the owned Store and
Keys are dropped and their original secret owners wipe unlocked material; no
accepted checkpoint mutation or output was prepared. This does not make missing
production G3, equal-root replication or full restore composition available.

`PreparedOpen` retains the consumed original opaque PRF during owner construction.
Its local locator is distinct from the canonical network record key. With the
native-records feature, `native_records` derives the original Keys passkey record
initializer from the same PRF/scope and consumes it through the existing Mesh
factory sharing the sole native runtime. No independent network is started here.
The generic `PasskeyRecords::new` is a trusted composition boundary: its locator and
authenticated record capability must belong to that same passkey/scope, never a
caller-selected JSON association. Only the original DFLT(1) schema is accepted.

`PasskeyRecords::checkpoint` forces `get(0, true)` in the original record engine.
It preserves the original authenticated observation floor and decodes the existing
passkey-root framing before returning the exact PRF-wrapped Keys bytes, canonical
record key and record sequence. The floor is retained even for malformed owner
bytes; this sequence is not a Keys local or lineage revision. Missing,
offline, invalid or unavailable data never becomes KnownAbsent or an empty
identity. The original native core refuses an offline forced read even when it
retains valid local ciphertext; a non-refreshed cache is not current authority.
Lookup performs no publication or restore installation. Native capability initialization may establish the original
empty record descriptor, which proves no identity or authenticated data absence.

`PreparedOpen::inspect_record` authenticates those exact retained bytes through
the original Keys checkpoint decoder. `inspector` lends the original narrow
wrapping capability to the trusted Authority for subsequent forced refreshes
after preparation is consumed. Public lineage/device/revision/time/digest claims
do not grant current membership or prove a globally latest lineage. The composer
must join original current-lineage provenance, monotonic record observations,
live authenticated passkey/device membership, the clock floor and owner intent.
The inspector must be owned inside custody and dropped on invalidation; consuming
`Vault::lock` drops Authority with Keys after wiping the shared Store. Independently
retained inspectors are not revoked by locking another Keys instance.

PasskeyRecords reuses the original `cvlt.passkey-root.v1` framing, `cprz` portable
compression and Padme padding before the actual engine's VLD0 encryption.
`publish` accepts the original owner-selected sequence and already-wrapped payload
from a durable outbox. Queued, Replicated and Conflict remain original engine
outcomes; none acknowledges an application operation or grants lineage authority.
The original sequence floor refuses rollback. Native startup is prepare → publish
retained committed values → attach; a failed/cancelled attach never permits an
offline write fallback. `close` forwards actual native record shutdown.

The canonical DFLT(1) subkey limit is 32 KiB, while Storage allows compound
checkpoints up to 8 MiB. The original codec refuses payloads that cannot fit after
packing; no alternate chunk format, truncation or pruning is introduced. This does
not claim that a full compound checkpoint fits, restores or is replicated.
Actual online forced reads, native/browser runtime composition and complete
active-member restore remain acceptance obligations.


`verify_lineage` joins the original Keys Receipt/device attestation and exact
`Receipt::passkey_challenge` to the original Keyhole assertion verifier. The
credential descriptor must come from `VerifiedCharter::passkey_binding`, which
checks the original Policy signature, member mapping, policy epoch and current
member/passkey revocations. The result borrows the actual current Charter and
original receipt/binding; callers cannot construct, clone or deserialize the
observation. Access checks its exclusive deadline and observation clock floor.
In the live Foyer composition, verify and use this observation inside the
synchronous current-Policy callback; reborrow and reverify after every await.

This observation establishes one passkey-attested change only. It neither
selects globally current lineage nor authorizes Keys, creates membership, proves
Records freshness or opens custody. The original device roster/session checks,
lineage predecessor/conflict rules, current checkpoint comparison and exact owner
intent remain separate obligations. Original Keys same-epoch adoption permits
only a higher revision with unchanged root/identity and a superset of devices;
this verifier adds no general revision/tie comparator or winner cache.

The server-backed native fixture creates an actual original Keys receipt through
a fixture-only one-shot Create authority, obtains actual maintained-authenticator
assertions and a registered SQL Keyhole descriptor, and signs original Charter
publications and Policy binding bytes. It exercises only original cryptographic
composition, including a valid assertion for a different challenge and actual
server-revoked credential IDs. It does not stand in for live admission or a G3
production Authority. Browser execution, retained publication/outbox integration,
full coverage and end-to-end adoption remain pending.


Public lineage evidence retention uses the original local Store boundary.
`LineageEvidence::prepare` runs the original verifier synchronously under the
current Policy borrow and returns a transient `PreparedLineageEvidence`. Its
verification applies to preparation only; it carries no currentness across an
await. Retained values loaded later cannot construct that preparation type or an
Authority. `LineageEvidence::verify` must reborrow actual current Policy for use.

`Vault::retain_lineage_evidence` snapshots the original Store version, reads the
actual Keys pending Receipt, then requires the same Store version and exact
Receipt at its separate Store transaction. It preserves Keys ciphertext, pending
Receipt and every existing outbox value. The existing Batch requires a real Keys
CAS, so it is not used to force a fake transition, and Keys::acknowledge is never
called here. Original Store version/CAS checks fence concurrent writes. Once the
write begins, cancellation or any failed completion locks Keys; original Storage
also closes uncertain/cancelled reads before its backend await. Reopen actual
backend bytes and reconcile the exact Store operation and values, without
regenerating Keys changes or asserting an outcome from a timeout.

The three local owner namespaces `lineage-receipt`, `lineage-assertion` and
`lineage-binding` use the original Receipt operation as their record key. Receipt
and Assertion use their original serde representations; binding bytes remain
exactly the original signed COSE. All three are written atomically and have an
aggregate 1 MiB limit. Partial, malformed, differently scoped or mismatched-key
retained records are refused; stored assertions/bindings still require original
cryptographic verification against current Policy. These are opaque domain-owned
values inside the existing encrypted Store, not a DHT/wire bundle, publication
format, accepted-lineage cache or a new transport. No outgoing output is invented
or acknowledged. The returned original Store receipt proves local persistence
only. Publication, actual transport acknowledgement and current-lineage/Authority
composition remain separate unfinished work.

Native test source retains genuine Keys/passkey/Charter evidence through the
original atomic file backend. It exercises reopen/lost replies, cancellation
before or after the real CAS, uncertain completion, an actual competing writer,
unchanged Keys/output values, pending-receipt mismatch, incomplete/corrupt/oversize
local values and fresh revocation/expiry refusal. Fault injection only delays or
loses the original backend result; it never fabricates accepted custody/evidence.
Native/browser execution and full coverage remain pending.

Compound checkpoint chunking is described in [COMPOUND-RECORDS.md](COMPOUND-RECORDS.md).
It preserves original passkey-root retention, uses only original authenticated
Records operations and exact Storage wire, and cannot grant lineage/currentness
or infer absence. Its production bootstrap and equal-passkey Store wrapping gaps
remain explicit.

Approved common-root recovery uses a bounded v2 passkey-root payload containing
original sealed Keys bytes and receipt/assertion/issuer-certificate evidence.
Legacy v1 can be read but cannot silently open a compound Store. `PreparedOpen`
verifies original evidence under the current Charter; authorization must still
force the current lineage read and live HTTPS device check. The temporary
bootstrap lends only fixed compound Records custody and a borrowed StoreCipher.
Restore checks the exact selected Keys ciphertext digest before destination CAS,
then rechecks current authority and the clock before returning the original Vault.
Restoring its Wallet and other owners remains the enclosing composer's job.

`migrate_legacy` is the explicit unpublished PRF-layout migration. Keys supplies
the current root wrapper inside its original fenced commit; KeyStore forwards
it into the same Store transaction as Keys bytes and companion values/outputs.
The random data key is preserved. No public cipher getter or alternate accepted
checkpoint is introduced. Missing/unavailable input never selects creation.
The production current-lineage authority/bootstrap read-key sequencing remains
an explicit integration boundary; these APIs alone do not qualify full restore.


`PreparedOpen::create_initial` is the explicit first-registration composition.
Its injected Keys Authority must consume original registration provenance; the
method never infers Create from missing Records or a failed restoration. Before
Keys generates its random root, the original destination backend must actually
report absence. Existing bytes and failed reads refuse this path.

The Initial Keys adapter consumes its destination before preparation. Original
`cwst::Memory` builds one complete checkpoint under the borrowed common-root
StoreCipher with Keys, companion mutations and outputs. This is ephemeral
preparation only. Original `Store::restore_checked` authenticates those exact
bytes, scope, version one, operation and Keys replacement before the destination's
single empty-state CAS. Only that durable CAS followed by local publication makes
the adapter Ready and reports Committed to Keys. No empty durable intermediate,
PRF-only compound wrapper, exported cipher or acknowledged memory receipt exists.

Cancellation, conflict and uncertain completion leave the adapter Spent. Even
cancellation after durable CAS but before local Ready requires reopening the exact
destination and reconciling its operation; it cannot retry Create. The original
pending Keys Receipt is retained. This local commit neither publishes genesis nor
establishes current lineage, membership, Wallet or device authority. Original
certified genesis publication and sealed registration continuation remain the
production composer's separate obligations. No restoration authority changes.

Written owner scenarios cover the original Keys common-root wrapper, exact pending
Receipt, one destination CAS, companion atomicity, unavailable/nonempty reads,
competing writes, cancellation before/after CAS and before Ready, unknown completion,
and authenticated scope/version/operation/Keys mismatches. These new tests have
not executed; no native/browser or coverage qualification is claimed.

# SSVT Plugin (Synergyst Skill Verification Token)

Server-side cryptographic verification, module policy enforcement, and client inspection plugin for Minecraft 1.20+ Paper and Spigot servers.

SSVT acts as the authoritative server endpoint for the Skill Verification Token (SVT) protocol (version 3). It validates client-side mod installations through Ed25519 digital signatures, issues single-use challenge nonces to prevent replay attacks, enforces server-configured functional rules over client modules, relays verified peer presence across clients, and provides on-demand inspection tools for server administrators.

---

## Architecture Overview

SSVT operates entirely through the standard Bukkit plugin messaging pipeline on the channel `synergystcrystal:svt`. It does not require native packet libraries or network protocol injection.

```
Client (SVT Client Mod)                      Server (SSVT Plugin)
       |                                                 |
       | ------------ C2S_HELLO (0x01) ----------------> |  Version gate check
       | <----------- S2C_SERVER_CHALLENGE (0x01) ------ |  Issues 16-byte nonce
       |                                                 |
       | ------------ C2S_HANDSHAKE (0x02) ------------> |  Signature & hash check
       | <----------- S2C_POLICY_MANIFEST (0x07) ------- |  Applies module rules
       | <----------- S2C_PEER_PRESENT (0x03) ---------- |  Broadcasts to peers
       |                                                 |
       | ------------ C2S_POLICY_ACK (0x03) -----------> |  Compliance audit
       |                                                 |
       | <----------- S2C_QUERY_REQUEST (0x09) --------- |  Admin on-demand check
       | ------------ C2S_QUERY_RESPONSE (0x04) -------> |  Inspection report
```

### Component Structure

- **Transport layer**: Uses `SvtByteBuf` to serialize and deserialize data in Minecraft's native `PacketByteBuf` format, preventing data misalignment caused by standard Java or Bukkit I/O streams.
- **Challenge manager**: Issues cryptographically secure, 16-byte nonces stored in an in-memory concurrent map with a strict 30-second time-to-live expiration window.
- **Peer registry**: Maintains runtime state for authenticated players, tracking account identifiers, public key hashes, client versions, capability bitmasks, and active module sets.
- **Policy store**: Loads and validates server-wide module policies from `policy.json`, supporting hot reloads without disconnecting verified clients.
- **Cryptographic engine**: Reconstructs canonical manifest hashes from module bit sets and evaluates Ed25519 signatures against client-provided X.509 public keys.
- **Revocation store**: Persists revoked public key hashes in `blocklist.txt`, denying verification to blocked client identities regardless of Minecraft account or username changes.
- **Audit engine**: Appends JSON Lines entries to `audit.jsonl` detailing every handshake attempt, client fingerprint, configuration hash, and verification verdict.

---

## Wire Protocol Specification

The SVT protocol uses raw binary payloads prefixed with a single-byte packet identifier. All variable-length integers (`VarInt`), length-prefixed strings, UUIDs, and byte arrays match the internal Minecraft network codec.

### Client to Server Packets (C2S)

| ID | Name | Payload structure | Description |
|---|---|---|---|
| `0x01` | `C2S_HELLO` | `VarInt` protocol, `String` version, `Byte` capabilities | Signals client presence and requests a challenge nonce |
| `0x02` | `C2S_HANDSHAKE` | `String` version, `Byte` capabilities, `ByteArray` pubKey, `LongArray` modules, `String` configHash, `ByteArray` signature | Delivers cryptographic credentials, active modules, and signature |
| `0x03` | `C2S_POLICY_ACK` | `VarInt` policyVersion, `LongArray` activeModules | Confirms module states after policy application |
| `0x04` | `C2S_QUERY_RESPONSE` | `VarInt` queryType, `Byte` status, payload | Returns inspection data requested by an administrator |

### Server to Client Packets (S2C)

| ID | Name | Payload structure | Description |
|---|---|---|---|
| `0x01` | `S2C_SERVER_CHALLENGE` | `ByteArray` nonce, `VarInt` protocolVersion | Sends a 16-byte single-use nonce to the client |
| `0x02` | `S2C_PROTOCOL_REJECT` | `Byte` reasonCode, `String` message | Notifies client of verification rejection |
| `0x03` | `S2C_PEER_PRESENT` | `UUID` id, `String` name, `String` version, `Byte` capabilities | Announces a verified client to existing peers |
| `0x04` | `S2C_PEER_LEFT` | `UUID` id | Announces peer disconnection to remaining peers |
| `0x05` | `S2C_PEER_STATS` | `UUID` id, `String` data | Relays public statistics payload to verified peers |
| `0x06` | `S2C_PEER_COMBAT` | `UUID` id, `String` data | Relays combat summary report to verified peers |
| `0x07` | `S2C_POLICY_MANIFEST` | `VarInt` policyVersion, `VarInt` ruleCount, repeated rules | Instructs client to enforce module states |
| `0x08` | `S2C_ADMIN_MESSAGE` | `Byte` severity, `String` message | Displays an administrative toast or notice on the client |
| `0x09` | `S2C_QUERY_REQUEST` | `VarInt` queryType | Requests inspection data from the client |
| `0x0A` | `S2C_FEATURE_GRANT` | `VarInt` moduleOrdinal, `Byte` granted | Dynamically grants or revokes a restricted module |

### Capability Flags

Capabilities are transmitted as a single-byte bitmask in presence and handshake packets:

- `0x01` (`CAP_HANDSHAKE_ONLY`): Client requests verification without being announced to other peers.
- `0x02` (`CAP_STATS_VISIBLE`): Client opts in to broadcasting telemetry statistics blobs.
- `0x04` (`CAP_COMBAT_VISIBLE`): Client opts in to broadcasting combat summary reports.
- `0x08` (`CAP_NAMEPLATE_VISIBLE`): Client permits rendering custom nameplate markers for verified peers.

### Reject Reason Codes

When a verification attempt fails, the server dispatches `S2C_PROTOCOL_REJECT` with an explicit reason code:

- `0` (`REJECT_UNKNOWN`): Unspecified internal server error.
- `1` (`REJECT_SIGNATURE`): Ed25519 signature could not be verified against the public key and nonce.
- `2` (`REJECT_OUTDATED`): Client mod version is lower than `minModVersion`.
- `3` (`REJECT_BLOCKED`): Public key hash is present in `blocklist.txt`.
- `4` (`REJECT_POLICY`): Client configuration hash is not included in `approvedConfigHashes`.
- `5` (`REJECT_MALFORMED`): Packet failed bounds validation, length checks, or hash binding.

---

## Cryptographic Handshake Pipeline

Verification treats all client inputs as untrusted and processes them in a deterministic order:

```
[Inbound C2S_HANDSHAKE]
         │
         ├── 1. Challenge Consumption ──> Nonce missing or expired (>30s)? ──> REJECT_MALFORMED
         │
         ├── 2. Version Gate ───────────> Version < minModVersion? ─────────> REJECT_OUTDATED
         │
         ├── 3. Identity Check ─────────> SHA-256(pubKey) in blocklist? ────> REJECT_BLOCKED & Kick
         │
         ├── 4. Hash Binding ───────────> SHA-256(canonical) != configHash? ─> REJECT_MALFORMED
         │
         ├── 5. Configuration Gate ─────> Whitelist on & hash not approved? ─> REJECT_POLICY
         │
         └── 6. Signature Check ────────> Ed25519_Verify(pubKey, payload) ──> REJECT_SIGNATURE
                                                    │
                                                    ▼
                                           [Peer Registered]
```

### Verification Invariants

1. **Replay protection**: The challenge manager consumes the player's nonce immediately. Captured handshakes cannot be reused for subsequent connections.
2. **Canonical hash binding**: The server constructs a canonical byte buffer containing each module bitmask word as eight big-endian bytes followed by the UTF-8 bytes of the mod version string. It computes the SHA-256 digest and asserts equality with `configHash`. Clients cannot misrepresent module states without invalidating this digest.
3. **Signature payload**: The signed payload consists of the 16-byte server nonce concatenated with the 32-byte raw SHA-256 manifest hash. The Ed25519 signature must prove possession of the private key corresponding to the supplied X.509 public key.
4. **Identity fingerprinting**: The server derives `keyHash` by hashing the X.509 public key with SHA-256 (64 hex characters). The public fingerprint corresponds to the first 8 hex characters.

---

## Module System and Policy Enforcement

The mod exposes discrete functional modules represented as ordinals within an array of 64-bit bitmask words.

### Module Catalogue

| Ordinal | Identifier | Display name | Functional category |
|---|---|---|---|
| 0 | `FAST_ATTACK_PLACE` | Fast Attack / Place | Crystal placement and attack pacing |
| 1 | `ANTI_SHUFFLE` | Anti-Shuffle | Item count prediction compensation |
| 2 | `NO_SWING_ANIMATION` | No Crystal Swing | Suppression of held item bobbing |
| 3 | `ANCHOR_ANTI_AIRPLACE` | Anchor Anti-Airplace | Overworld respawn anchor click safety |
| 4 | `ANCHOR_GHOST_FIX` | Anchor Ghost Block Fix | Client-side anchor block removal prediction |
| 5 | `CUSTOM_BLOCK_OUTLINE` | Custom Block Outline | Custom RGB block selection rendering |
| 6 | `PACKET_OPTIMIZATION` | Packet Optimization | Netty socket options and flush batching |
| 7 | `PACKET_PRIORITIZATION` | Packet Prioritization | Immediate flushing of interaction packets |
| 8 | `ADAPTIVE_SEND_RATE` | Adaptive Send Rate | Jitter-based packet budget reduction |
| 9 | `INVENTORY_RESYNC` | Inventory Resync | Periodic screen handler synchronization |
| 10 | `COMBAT_ANALYTICS` | Combat Analytics | Zero-allocation combat telemetry engine |
| 11 | `COMBAT_DEBUG_OVERLAY` | Combat Debug Overlay | In-game telemetry HUD overlay |
| 12 | `AI_ANALYSIS` | AI Analysis | Automated external LLM coaching integration |
| 13 | `CRYSTAL_VISUAL_LOD` | Crystal Visual LOD | Level-of-detail crystal geometry culling |
| 14 | `EXPLOSION_PARTICLE_THROTTLE`| Explosion Particle Throttle | Particle creation throttling per 50 ms window |
| 15 | `NO_CAMERA_SHAKE` | No Damage Camera Tilt | Suppression of hurt camera roll transforms |
| 16 | `COMBAT_FOV_LOCK` | Combat FOV Lock | Fixed field of view during combat sessions |
| 17 | `BOT_TRAINING` | Bot Training | Automated training interaction routines |

### Enforcement Modes

The server dictates client module states using four enforcement modes:

- `ALLOW`: Leaves the module state under the control of the client's local configuration.
- `FORBID`: Instructs the client to disable the module.
- `REQUIRE`: Instructs the client to enable the module.
- `GRANT_ONLY`: Forces the module off unless an operator explicitly grants it via `/svt grant`.

When a rule is marked as `mandatory: true`, the client must return a matching state in its subsequent `C2S_POLICY_ACK`. If the client reports non-compliance, it is disconnected immediately.

---

## Identity Revocation and Blocklisting

The blocklist provides key-based client revocation independent of Minecraft accounts.

- **Storage**: Key hashes are stored in `plugins/SynergystSvt/blocklist.txt`, formatted as one 64-character lowercase hex string per line.
- **Account agility mitigation**: Because the blocklist tracks the SHA-256 hash of the client's persistent Ed25519 public key, players changing their Minecraft username or connecting via alternative accounts are rejected as long as they reuse their local identity file.
- **Dynamic revocation**: Running `/svt block <player>` immediately registers the peer's public key hash in the blocklist, writes the file to disk, and disconnects the player.

---

## Administrative Inspection and Queries

Administrators holding the `svt.admin` permission can query active clients for diagnostics without client-side execution prompts.

```
Admin                     Server (SynergystSvt)                     Target Client
  |                                 |                                     |
  | --- /svt query <player> <type> ->|                                     |
  |                                 | --- S2C_QUERY_REQUEST (0x09) ------> |
  |                                 |                                     | Client inspects state
  |                                 | <--- C2S_QUERY_RESPONSE (0x04) ---- |
  | <--- Formatted diagnostic text - |                                     |
```

### Supported Query Types

- `MODULE_STATE`: Requests the client's active module bit set. Returns the total count of active modules.
- `CONFIG_HASH`: Requests the client's canonical configuration hash.
- `INTEGRITY_HASH`: Requests the SHA-256 digest of the compiled core classes inside the client's JAR file.
- `STATS_SNAPSHOT`: Requests the client's lifetime combat telemetry aggregates (sessions, deaths, survivals, crystals placed).
- `COMBAT_SUMMARY`: Requests a summary of the client's most recent completed combat session (duration, kills, placements, outcome).

Clients configured with `svtAllowServerQueries: false` respond with status `QUERY_DENIED`. Requests for unavailable data (such as combat reports before any fight occurs) return status `QUERY_UNSUPPORTED`.

---

## Audit Logging

Every handshake attempt is recorded synchronously in `plugins/SynergystSvt/audit.jsonl` using JSON Lines format.

```json
{"ts":1774836660000,"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Notch","keyFingerprint":"a1b2c3d4","modVersion":"v2.1.16","protocolVersion":3,"moduleCount":14,"configHash":"8f4b2...","verdict":"VERIFIED"}
```

Logged verdict types:
- `VERIFIED`: Handshake completed successfully.
- `REJECT_OUTDATED_ON_HELLO`: Denied on initial presence due to mod version.
- `REJECT_OUTDATED`: Denied during handshake due to mod version.
- `REJECT_BLOCKED`: Denied due to presence in `blocklist.txt`.
- `REJECT_MALFORMED`: Denied due to buffer errors, missing challenges, or invalid hash binding.
- `REJECT_POLICY`: Denied due to configuration hash whitelist mismatch.
- `REJECT_SIGNATURE_INVALID`: Denied due to Ed25519 signature failure.
- `KICK_MANDATORY_<MODULE>`: Disconnected after acknowledging non-compliance with a mandatory rule.

---

## Configuration Reference

The plugin configuration is located at `plugins/SynergystSvt/policy.json`.

```json
{
  "policyVersion": 1,
  "minModVersion": "v2.1.16",
  "requireConfigWhitelist": false,
  "approvedConfigHashes": [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  ],
  "rules": {
    "FAST_ATTACK_PLACE": {
      "mode": "ALLOW",
      "mandatory": false
    },
    "ANTI_SHUFFLE": {
      "mode": "ALLOW",
      "mandatory": false
    },
    "BOT_TRAINING": {
      "mode": "FORBID",
      "mandatory": true
    },
    "AI_ANALYSIS": {
      "mode": "GRANT_ONLY",
      "mandatory": false
    },
    "PACKET_PRIORITIZATION": {
      "mode": "REQUIRE",
      "mandatory": true
    }
  }
}
```

### Configuration Keys

- `policyVersion`: Integer tracking the policy revision. Incremented versions force re-acknowledgement.
- `minModVersion`: Minimum acceptable client version string. Evaluated leniently across numeric components.
- `requireConfigWhitelist`: Enforces that incoming client configuration hashes must exist in `approvedConfigHashes`.
- `approvedConfigHashes`: Array of approved SHA-256 configuration hex hashes.
- `rules`: Map associating module identifiers with an enforcement mode (`ALLOW`, `FORBID`, `REQUIRE`, `GRANT_ONLY`) and a `mandatory` flag.

---

## Command Reference

All administration commands are executed via `/svt` and require the `svt.admin` permission node (defaults to server operators).

```
/svt list                                      Lists all verified peers, versions, and fingerprints
/svt inspect <player>                          Displays module bitmask and hash details for a player
/svt query <player> <type>                     Sends an on-demand inspection request
/svt grant <player> <module>                   Grants permission for a GRANT_ONLY module
/svt block <player>                            Revokes a player's public key and disconnects them
/svt unblock <keyHash>                         Removes a key hash from blocklist.txt
/svt kick <player> [reason]                    Disconnects a player with a specified reason
/svt msg <player> <info|warn|error> <text>     Sends an administrative notification toast
/svt policy reload                             Reloads policy.json and pushes updates to peers
/svt audit [lines]                             Prints recent entries from audit.jsonl
```

---

## Installation and Setup

1. Place the compiled `SynergystSvt.jar` into the server `plugins/` directory.
2. Start the server once to generate defaults: `plugins/SynergystSvt/policy.json`, `blocklist.txt`, and `audit.jsonl`.
3. Adjust `policy.json` to configure mandatory module constraints or minimum mod versions for your server.
4. Execute `/svt policy reload` to apply configuration changes without restarting.

Clients running the Synergyst Crystal Optimizer mod announce themselves automatically upon joining. Vanilla clients and unmodified clients do not send SVT packets and are ignored by the verification system.

## License

This software is released under the Zero-Clause BSD (0BSD) License. Refer to the LICENSE file for details.
package synergyst.svt.plugin.net;

import org.bukkit.Bukkit;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.plugin.messaging.PluginMessageListener;
import synergyst.svt.plugin.SvtPlugin;
import synergyst.svt.plugin.model.SvtPolicy;
import synergyst.svt.plugin.store.SvtPolicyStore;
import synergyst.svt.plugin.crypto.SvtCrypto;
import synergyst.svt.plugin.crypto.SvtVersion;
import synergyst.svt.plugin.model.SvtModule;
import synergyst.svt.plugin.model.SvtPeer;
import synergyst.svt.plugin.model.SvtPolicyRule;
import synergyst.svt.plugin.model.SvtQueryType;
import synergyst.svt.plugin.protocol.SvtByteBuf;
import synergyst.svt.plugin.protocol.SvtProtocol;
import synergyst.svt.plugin.store.SvtAuditLog;
import synergyst.svt.plugin.store.SvtBlocklist;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Receives and processes inbound SVT packets from clients.
 *
 * <h2>Hostile input</h2>
 * The byte array delivered by Bukkit originates from a client and is
 * treated as hostile. Decoding is performed with {@link SvtByteBuf},
 * which enforces length limits and bounds checks. Any decode failure is
 * caught, logged, and results in a malformed rejection rather than a
 * propagated exception.
 *
 * <h2>Handshake pipeline</h2>
 * A HELLO triggers a challenge. A HANDSHAKE is verified through the
 * version gate, hash binding, config whitelist, blocklist, and
 * signature check before the peer is registered and the policy is sent.
 * A POLICY_ACK is checked against mandatory rules. A QUERY_RESPONSE is
 * routed to the administrator who requested it.
 */
public final class SvtChannelListener implements PluginMessageListener {

    private final SvtPlugin plugin;
    private final Logger logger;
    private final SvtMessenger messenger;
    private final SvtPeerRegistry registry;
    private final SvtChallengeManager challenges;
    private final SvtPolicyStore policyStore;
    private final SvtBlocklist blocklist;
    private final SvtAuditLog audit;

    /**
     * Pending query requesters keyed by target player UUID. Maps to the
     * administrator awaiting the response.
     */
    private final Map<UUID, UUID> pendingQueries = new ConcurrentHashMap<>();

    public SvtChannelListener(SvtPlugin plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.messenger = plugin.messenger();
        this.registry = plugin.registry();
        this.challenges = plugin.challenges();
        this.policyStore = plugin.policyStore();
        this.blocklist = plugin.blocklist();
        this.audit = plugin.audit();
    }

    /**
     * Registers a pending query so the response can be routed back to
     * the requesting administrator.
     *
     * @param target    the inspected player UUID
     * @param requester the administrator UUID
     */
    public void registerPendingQuery(UUID target, UUID requester) {
        pendingQueries.put(target, requester);
    }

    @Override
    public void onPluginMessageReceived(String channel, Player player, byte[] message) {
        if (!SvtProtocol.CHANNEL.equals(channel)) {
            return;
        }
        try {
            SvtByteBuf buf = SvtByteBuf.reader(message);
            byte packetId = buf.readByte();
            switch (packetId) {
                case SvtProtocol.C2S_HELLO -> handleHello(player, buf);
                case SvtProtocol.C2S_HANDSHAKE -> handleHandshake(player, buf);
                case SvtProtocol.C2S_POLICY_ACK -> handlePolicyAck(player, buf);
                case SvtProtocol.C2S_QUERY_RESPONSE -> handleQueryResponse(player, buf);
                default -> logger.warning("Unknown SVT packet id " + packetId
                        + " from " + player.getName());
            }
        } catch (SvtByteBuf.SvtDecodeException e) {
            logger.warning("Malformed SVT packet from " + player.getName()
                    + ": " + e.getMessage());
            messenger.sendReject(player, SvtProtocol.REJECT_MALFORMED, "decode error");
        } catch (Exception e) {
            logger.warning("Error handling SVT packet from " + player.getName()
                    + ": " + e.getMessage());
        }
    }

    /* ═══════════════════ HELLO ═══════════════════ */

    private void handleHello(Player player, SvtByteBuf buf) {
        int protocolVersion = buf.readVarInt();
        String modVersion = buf.readString(SvtProtocol.MAX_VERSION_LEN);
        buf.readByte(); // capabilities, re-read authoritatively from handshake

        SvtPolicy policy = policyStore.policy();
        if (!SvtVersion.satisfies(modVersion, policy.minModVersion())) {
            messenger.sendReject(player, SvtProtocol.REJECT_OUTDATED,
                    "requires " + policy.minModVersion());
            audit.record(player.getUniqueId().toString(), player.getName(),
                    "n/a", modVersion, protocolVersion, 0, "n/a",
                    "REJECT_OUTDATED_ON_HELLO");
            return;
        }

        byte[] nonce = challenges.issue(player.getUniqueId());
        messenger.sendChallenge(player, nonce);
        logger.info("SVT HELLO from " + player.getName()
                + " protocol " + protocolVersion + " version " + modVersion);
    }

    /* ═══════════════════ HANDSHAKE ═══════════════════ */

    private void handleHandshake(Player player, SvtByteBuf buf) {
        String modVersion = buf.readString(SvtProtocol.MAX_VERSION_LEN);
        byte capabilities = buf.readByte();
        byte[] pubKey = buf.readByteArray(SvtProtocol.MAX_PUBLIC_KEY_LEN);
        long[] moduleBits = buf.readLongArray(SvtProtocol.MAX_MANIFEST_WORDS);
        String configHash = buf.readString(SvtProtocol.MAX_CONFIG_HASH_LEN);
        byte[] signature = buf.readByteArray(SvtProtocol.MAX_SIGNATURE_LEN);

        UUID uuid = player.getUniqueId();
        String name = player.getName();
        SvtPolicy policy = policyStore.policy();

        String keyHash = SvtCrypto.keyHash(pubKey);
        String fingerprint = SvtCrypto.fingerprint(keyHash);
        int moduleCount = SvtModule.byOrdinal(0) == null ? 0 : countBits(moduleBits);

        byte[] nonce = challenges.consume(uuid);
        if (nonce == null) {
            reject(player, SvtProtocol.REJECT_MALFORMED, "no active challenge",
                    name, modVersion, moduleCount, configHash);
            return;
        }

        if (!SvtVersion.satisfies(modVersion, policy.minModVersion())) {
            reject(player, SvtProtocol.REJECT_OUTDATED,
                    "requires " + policy.minModVersion(),
                    name, modVersion, moduleCount, configHash);
            return;
        }

        if (blocklist.isBlocked(keyHash)) {
            reject(player, SvtProtocol.REJECT_BLOCKED, "identity revoked",
                    name, modVersion, moduleCount, configHash);
            kickMandatory(player, "Your mod identity is blocked on this server.");
            return;
        }

        byte[] rawHash = SvtCrypto.manifestHash(moduleBits, modVersion);
        if (rawHash == null || !SvtCrypto.toHex(rawHash).equals(configHash)) {
            reject(player, SvtProtocol.REJECT_MALFORMED, "hash binding failed",
                    name, modVersion, moduleCount, configHash);
            return;
        }

        if (policy.requireConfigWhitelist() && !policy.isConfigApproved(configHash)) {
            reject(player, SvtProtocol.REJECT_POLICY, "config not approved",
                    name, modVersion, moduleCount, configHash);
            return;
        }

        byte[] signedPayload = concat(nonce, rawHash);
        if (!SvtCrypto.verify(pubKey, signedPayload, signature)) {
            reject(player, SvtProtocol.REJECT_SIGNATURE, "invalid signature",
                    name, modVersion, moduleCount, configHash);
            return;
        }

        SvtPeer peer = new SvtPeer(uuid, name, modVersion, capabilities,
                moduleBits, configHash, keyHash, System.currentTimeMillis());
        registry.put(peer);

        messenger.sendPolicy(player, policy);
        broadcastPresence(peer);

        audit.record(uuid.toString(), name, fingerprint, modVersion,
                SvtProtocol.VERSION, moduleCount, configHash, "VERIFIED");
        logger.info("SVT verified " + name + " fingerprint " + fingerprint
                + " modules " + moduleCount);
    }

    private void reject(Player player, byte reason, String message,
                        String name, String modVersion, int moduleCount,
                        String configHash) {
        messenger.sendReject(player, reason, message);
        audit.record(player.getUniqueId().toString(), name, "n/a", modVersion,
                SvtProtocol.VERSION, moduleCount, configHash,
                "REJECT_" + SvtProtocol.rejectReasonName(reason));
        logger.info("SVT rejected " + name + ": "
                + SvtProtocol.rejectReasonName(reason) + " " + message);
    }

    private void kickMandatory(Player player, String reason) {
        Bukkit.getScheduler().runTask(plugin,
                () -> player.kickPlayer(reason));
    }

    /* ═══════════════════ POLICY_ACK ═══════════════════ */

    private void handlePolicyAck(Player player, SvtByteBuf buf) {
        int policyVersion = buf.readVarInt();
        long[] activeBits = buf.readLongArray(SvtProtocol.MAX_MANIFEST_WORDS);

        SvtPolicy policy = policyStore.policy();
        SvtModule violated = null;

        for (SvtPolicyRule rule : policy.rules()) {
            if (!rule.mandatory() || !rule.isEnforcing()) {
                continue;
            }
            Boolean required = rule.forcedState();
            if (required == null) {
                continue;
            }
            boolean actual = rule.module().isSet(activeBits);
            if (actual != required) {
                violated = rule.module();
                break;
            }
        }

        if (violated != null) {
            logger.warning("SVT mandatory violation by " + player.getName()
                    + " on module " + violated.name());
            audit.record(player.getUniqueId().toString(), player.getName(),
                    "n/a", "n/a", SvtProtocol.VERSION, 0, "n/a",
                    "KICK_MANDATORY_" + violated.name());
            kickMandatory(player,
                    "A required setting could not be enforced: " + violated.displayName());
        } else {
            logger.info("SVT policy ack from " + player.getName()
                    + " policy v" + policyVersion + " compliant");
        }
    }

    /* ═══════════════════ QUERY_RESPONSE ═══════════════════ */

    private void handleQueryResponse(Player player, SvtByteBuf buf) {
        int typeOrdinal = buf.readVarInt();
        byte status = buf.readByte();

        SvtQueryType type = typeOrdinal >= 0
                && typeOrdinal < SvtQueryType.values().length
                ? SvtQueryType.values()[typeOrdinal] : null;

        StringBuilder result = new StringBuilder();
        result.append("Query ").append(type == null ? typeOrdinal : type.name())
                .append(" from ").append(player.getName()).append(": ");

        if (status == SvtProtocol.QUERY_DENIED) {
            result.append("denied by user");
        } else if (status == SvtProtocol.QUERY_UNSUPPORTED) {
            result.append("unsupported");
        } else if (type == null) {
            result.append("unknown type");
        } else {
            appendPayload(result, type, buf);
        }

        UUID requester = pendingQueries.remove(player.getUniqueId());
        String text = result.toString();
        Bukkit.getScheduler().runTask(plugin, () -> {
            CommandSender target = requester != null
                    ? Bukkit.getPlayer(requester) : null;
            if (target != null) {
                target.sendMessage("[SVT] " + text);
            } else {
                Bukkit.getConsoleSender().sendMessage("[SVT] " + text);
            }
        });
        logger.info("[SVT] " + text);
    }

    private void appendPayload(StringBuilder out, SvtQueryType type, SvtByteBuf buf) {
        switch (type) {
            case MODULE_STATE -> {
                long[] bits = buf.readLongArray(SvtProtocol.MAX_MANIFEST_WORDS);
                out.append("active modules ").append(countBits(bits));
            }
            case CONFIG_HASH -> out.append("config hash ")
                    .append(buf.readString(SvtProtocol.MAX_QUERY_STRING_LEN));
            case INTEGRITY_HASH -> out.append("integrity ")
                    .append(buf.readString(SvtProtocol.MAX_QUERY_STRING_LEN));
            case STATS_SNAPSHOT -> {
                int sessions = buf.readVarInt();
                int deaths = buf.readVarInt();
                int survived = buf.readVarInt();
                int crystals = buf.readVarInt();
                out.append("sessions ").append(sessions)
                        .append(" deaths ").append(deaths)
                        .append(" survived ").append(survived)
                        .append(" crystals ").append(crystals);
            }
            case COMBAT_SUMMARY -> {
                String fightId = buf.readString(SvtProtocol.MAX_QUERY_STRING_LEN);
                int duration = buf.readVarInt();
                int crystals = buf.readVarInt();
                int kills = buf.readVarInt();
                boolean died = buf.readByte() != 0;
                out.append("fight ").append(fightId)
                        .append(" duration ").append(duration)
                        .append(" crystals ").append(crystals)
                        .append(" kills ").append(kills)
                        .append(" died ").append(died);
            }
        }
    }

    /* ═══════════════════ Presence broadcast ═══════════════════ */

    private void broadcastPresence(SvtPeer arriving) {
        Player arrivingPlayer = Bukkit.getPlayer(arriving.uuid());
        for (SvtPeer other : registry.all()) {
            if (other.uuid().equals(arriving.uuid())) {
                continue;
            }
            if (!other.isHandshakeOnly() && arrivingPlayer != null) {
                messenger.sendPeerPresent(arrivingPlayer, other);
            }
            if (!arriving.isHandshakeOnly()) {
                Player otherPlayer = Bukkit.getPlayer(other.uuid());
                if (otherPlayer != null) {
                    messenger.sendPeerPresent(otherPlayer, arriving);
                }
            }
        }
    }

    /* ═══════════════════ Helpers ═══════════════════ */

    private static int countBits(long[] bits) {
        int count = 0;
        for (long word : bits) {
            count += Long.bitCount(word);
        }
        return count;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
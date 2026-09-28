package synergyst.svt.plugin.net;

import synergyst.svt.plugin.protocol.SvtProtocol;

import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Issues and tracks per connection handshake nonces.
 *
 * <p>A nonce is generated when a client sends its presence
 * announcement. The handshake signature must cover this nonce, which
 * ties the signature to the current connection and prevents replay of a
 * captured handshake. A nonce expires after a short window and is
 * consumed when the matching handshake is verified.</p>
 */
public final class SvtChallengeManager {

    private static final long EXPIRY_MS = 30_000L;

    private final SecureRandom random = new SecureRandom();
    private final Map<UUID, Entry> pending = new ConcurrentHashMap<>();

    private record Entry(byte[] nonce, long issuedAtMs) {}

    /**
     * Generates and stores a fresh nonce for a player.
     *
     * @param uuid the account UUID
     * @return the generated nonce bytes
     */
    public byte[] issue(UUID uuid) {
        byte[] nonce = new byte[SvtProtocol.CHALLENGE_NONCE_LEN];
        random.nextBytes(nonce);
        pending.put(uuid, new Entry(nonce, System.currentTimeMillis()));
        return nonce;
    }

    /**
     * Consumes and returns the pending nonce for a player if it exists
     * and has not expired.
     *
     * @param uuid the account UUID
     * @return the nonce bytes, or null if absent or expired
     */
    public byte[] consume(UUID uuid) {
        Entry entry = pending.remove(uuid);
        if (entry == null) {
            return null;
        }
        if (System.currentTimeMillis() - entry.issuedAtMs() > EXPIRY_MS) {
            return null;
        }
        return entry.nonce();
    }

    /**
     * Drops any pending nonce for a player.
     *
     * @param uuid the account UUID
     */
    public void clear(UUID uuid) {
        pending.remove(uuid);
    }
}
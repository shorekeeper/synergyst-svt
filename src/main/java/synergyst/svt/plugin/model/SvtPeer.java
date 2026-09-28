package synergyst.svt.plugin.model;

import synergyst.svt.plugin.crypto.SvtCrypto;
import synergyst.svt.plugin.protocol.SvtProtocol;

import java.util.UUID;

/**
 * State of a verified mod user held in memory for the duration of a
 * connection.
 *
 * @param uuid           the account UUID
 * @param name           the account name
 * @param modVersion     the reported mod version
 * @param capabilities   the capability bit field
 * @param moduleBits     the module manifest bit set
 * @param configHash     the reported config hash
 * @param keyHash        the full public key hash
 * @param handshakeAtMs  the time the handshake was verified
 */
public record SvtPeer(UUID uuid, String name, String modVersion,
                      byte capabilities, long[] moduleBits, String configHash,
                      String keyHash, long handshakeAtMs) {

    /**
     * Returns whether the peer requested handshake only visibility.
     *
     * @return whether the handshake only capability bit is set
     */
    public boolean isHandshakeOnly() {
        return (capabilities & SvtProtocol.CAP_HANDSHAKE_ONLY) != 0;
    }

    /**
     * Returns the short key fingerprint.
     *
     * @return the fingerprint
     */
    public String fingerprint() {
        return SvtCrypto.fingerprint(keyHash);
    }
}
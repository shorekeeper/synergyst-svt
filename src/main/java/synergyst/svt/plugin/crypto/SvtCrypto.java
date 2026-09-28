package synergyst.svt.plugin.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

/**
 * Cryptographic helpers for handshake verification.
 *
 * <p>All public methods treat their byte array inputs as hostile. Key
 * parsing and signature verification are wrapped so that malformed
 * input produces a negative result rather than propagating an
 * exception into the packet handler.</p>
 */
public final class SvtCrypto {

    private static final String ALGORITHM = "Ed25519";

    private SvtCrypto() {
        throw new AssertionError("Utility class");
    }

    /**
     * Verifies an Ed25519 signature over the given data using an X.509
     * encoded public key.
     *
     * @param publicKeyX509 the encoded public key bytes
     * @param data          the signed data
     * @param signature     the signature to verify
     * @return whether the signature is valid, false on any failure
     */
    public static boolean verify(byte[] publicKeyX509, byte[] data, byte[] signature) {
        try {
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(publicKeyX509));
            Signature sig = Signature.getInstance(ALGORITHM);
            sig.initVerify(pub);
            sig.update(data);
            return sig.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Recomputes the manifest hash from the module bit set and the mod
     * version using the client canonical layout.
     *
     * <p>The layout is each bit set word as eight big endian bytes,
     * followed by the UTF-8 bytes of the mod version. The result is the
     * raw SHA-256 digest.</p>
     *
     * @param bits       the module bit set
     * @param modVersion the mod version string
     * @return the digest bytes, or null on failure
     */
    public static byte[] manifestHash(long[] bits, String modVersion) {
        try {
            byte[] versionBytes = modVersion.getBytes(StandardCharsets.UTF_8);
            ByteBuffer buffer = ByteBuffer.allocate(bits.length * 8 + versionBytes.length);
            for (long word : bits) {
                buffer.putLong(word);
            }
            buffer.put(versionBytes);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(buffer.array());
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Returns the lower case hexadecimal encoding of a byte array.
     *
     * @param bytes the bytes
     * @return the hex string
     */
    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    /**
     * Computes the full SHA-256 hash of a public key, used as the
     * blocklist key identifier.
     *
     * @param publicKeyX509 the encoded public key
     * @return the 64 character hex hash, or null on failure
     */
    public static String keyHash(byte[] publicKeyX509) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return toHex(digest.digest(publicKeyX509));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Returns a short display fingerprint, the first eight characters
     * of the key hash.
     *
     * @param keyHash the full key hash
     * @return the fingerprint, or the string unknown if the hash is null
     */
    public static String fingerprint(String keyHash) {
        if (keyHash == null || keyHash.length() < 8) {
            return "unknown";
        }
        return keyHash.substring(0, 8);
    }
}
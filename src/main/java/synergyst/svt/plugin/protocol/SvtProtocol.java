package synergyst.svt.plugin.protocol;

/**
 * Wire protocol constants for the Skill Verification Token channel.
 *
 * <p>This class mirrors the client side protocol definition. The
 * numeric packet identifiers, reason codes, severities, statuses, and
 * length limits must match the client exactly. Any change here without
 * a corresponding client change breaks interoperability.</p>
 *
 * <h2>Transport</h2>
 * Traffic travels on the plugin message channel identified by
 * {@link #CHANNEL}. The server registers this channel on enable. A
 * client that does not advertise the channel receives nothing.
 *
 * <h2>Encoding</h2>
 * Packet bodies use the Minecraft {@code PacketByteBuf} encoding, not
 * the Bukkit or Guava data stream format. Variable length integers,
 * length prefixed strings, and length prefixed byte arrays follow the
 * conventions implemented in {@link SvtByteBuf}.
 */
public final class SvtProtocol {

    /** Protocol revision this plugin speaks. */
    public static final int VERSION = 3;

    /** Plugin message channel in namespace:path form. */
    public static final String CHANNEL = "synergystcrystal:svt";

    /* ═══════════════════ Client to server ids ═══════════════════ */

    public static final byte C2S_HELLO = 0x01;
    public static final byte C2S_HANDSHAKE = 0x02;
    public static final byte C2S_POLICY_ACK = 0x03;
    public static final byte C2S_QUERY_RESPONSE = 0x04;

    /* ═══════════════════ Server to client ids ═══════════════════ */

    public static final byte S2C_SERVER_CHALLENGE = 0x01;
    public static final byte S2C_PROTOCOL_REJECT = 0x02;
    public static final byte S2C_PEER_PRESENT = 0x03;
    public static final byte S2C_PEER_LEFT = 0x04;
    public static final byte S2C_PEER_STATS = 0x05;
    public static final byte S2C_PEER_COMBAT = 0x06;
    public static final byte S2C_POLICY_MANIFEST = 0x07;
    public static final byte S2C_ADMIN_MESSAGE = 0x08;
    public static final byte S2C_QUERY_REQUEST = 0x09;
    public static final byte S2C_FEATURE_GRANT = 0x0A;

    /* ═══════════════════ Reject reason codes ═══════════════════ */

    public static final byte REJECT_UNKNOWN = 0;
    public static final byte REJECT_SIGNATURE = 1;
    public static final byte REJECT_OUTDATED = 2;
    public static final byte REJECT_BLOCKED = 3;
    public static final byte REJECT_POLICY = 4;
    public static final byte REJECT_MALFORMED = 5;

    /* ═══════════════════ Admin message severity ═══════════════════ */

    public static final byte SEVERITY_INFO = 0;
    public static final byte SEVERITY_WARN = 1;
    public static final byte SEVERITY_ERROR = 2;

    /* ═══════════════════ Query response status ═══════════════════ */

    public static final byte QUERY_OK = 0;
    public static final byte QUERY_DENIED = 1;
    public static final byte QUERY_UNSUPPORTED = 2;

    /* ═══════════════════ Capability bit field ═══════════════════ */

    public static final byte CAP_HANDSHAKE_ONLY = 1 << 0;
    public static final byte CAP_STATS_VISIBLE = 1 << 1;
    public static final byte CAP_COMBAT_VISIBLE = 1 << 2;
    public static final byte CAP_NAMEPLATE_VISIBLE = 1 << 3;

    /* ═══════════════════ Length limits ═══════════════════ */

    public static final int MAX_VERSION_LEN = 32;
    public static final int MAX_NAME_LEN = 64;
    public static final int MAX_CONFIG_HASH_LEN = 128;
    public static final int MAX_CHALLENGE_NONCE_LEN = 64;
    public static final int MAX_REJECT_MSG_LEN = 256;
    public static final int MAX_ADMIN_MSG_LEN = 512;
    public static final int MAX_STATS_BLOB_LEN = 16384;
    public static final int MAX_PUBLIC_KEY_LEN = 256;
    public static final int MAX_SIGNATURE_LEN = 128;
    public static final int MAX_MANIFEST_WORDS = 8;
    public static final int MAX_POLICY_RULES = 128;
    public static final int MAX_QUERY_STRING_LEN = 256;

    /** Nonce length the server issues in a challenge. */
    public static final int CHALLENGE_NONCE_LEN = 16;

    private SvtProtocol() {
        throw new AssertionError("Constants holder");
    }

    /**
     * Returns a human readable name for a reject reason code.
     *
     * @param code the reason code
     * @return the reason name
     */
    public static String rejectReasonName(byte code) {
        return switch (code) {
            case REJECT_SIGNATURE -> "SIGNATURE_INVALID";
            case REJECT_OUTDATED  -> "MOD_OUTDATED";
            case REJECT_BLOCKED   -> "KEY_BLOCKED";
            case REJECT_POLICY    -> "POLICY_VIOLATION";
            case REJECT_MALFORMED -> "MALFORMED_PAYLOAD";
            default               -> "UNKNOWN";
        };
    }
}
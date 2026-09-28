package synergyst.svt.plugin.model;

/**
 * Server side mirror of the client module enumeration.
 *
 * <p>The ordinal order defines the bit position of each module in a
 * manifest bit set and in policy and query encodings. This order must
 * match the client enumeration exactly. Constants may be appended at
 * the end when the client appends them. Reordering or removing
 * constants changes the meaning of existing bit positions and requires
 * a protocol version bump on both sides.</p>
 */
public enum SvtModule {

    FAST_ATTACK_PLACE("Fast Attack / Place"),
    ANTI_SHUFFLE("Anti-Shuffle"),
    NO_SWING_ANIMATION("No Crystal Swing"),
    ANCHOR_ANTI_AIRPLACE("Anchor Anti-Airplace"),
    ANCHOR_GHOST_FIX("Anchor Ghost Block Fix"),
    CUSTOM_BLOCK_OUTLINE("Custom Block Outline"),
    PACKET_OPTIMIZATION("Packet Optimization"),
    PACKET_PRIORITIZATION("Packet Prioritization"),
    ADAPTIVE_SEND_RATE("Adaptive Send Rate"),
    INVENTORY_RESYNC("Inventory Resync"),
    COMBAT_ANALYTICS("Combat Analytics"),
    COMBAT_DEBUG_OVERLAY("Combat Debug Overlay"),
    AI_ANALYSIS("AI Analysis"),
    CRYSTAL_VISUAL_LOD("Crystal Visual LOD"),
    EXPLOSION_PARTICLE_THROTTLE("Explosion Particle Throttle"),
    NO_CAMERA_SHAKE("No Damage Camera Tilt"),
    COMBAT_FOV_LOCK("Combat FOV Lock"),
    BOT_TRAINING("Bot Training");

    private static final SvtModule[] VALUES = values();

    private final String displayName;

    SvtModule(String displayName) {
        this.displayName = displayName;
    }

    /**
     * Returns the human readable label.
     *
     * @return the display name
     */
    public String displayName() {
        return displayName;
    }

    /**
     * Resolves a module by ordinal, validating the index.
     *
     * @param ordinal the ordinal
     * @return the module, or null if out of range
     */
    public static SvtModule byOrdinal(int ordinal) {
        if (ordinal < 0 || ordinal >= VALUES.length) {
            return null;
        }
        return VALUES[ordinal];
    }

    /**
     * Resolves a module by its enum name, case insensitive.
     *
     * @param name the enum constant name
     * @return the module, or null if not found
     */
    public static SvtModule byName(String name) {
        if (name == null) {
            return null;
        }
        try {
            return valueOf(name.toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Tests whether a bit set marks this module active.
     *
     * @param bits the bit set
     * @return whether the module bit is set
     */
    public boolean isSet(long[] bits) {
        int word = ordinal() >> 6;
        if (word >= bits.length) {
            return false;
        }
        return (bits[word] & (1L << (ordinal() & 63))) != 0;
    }
}
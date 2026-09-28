package synergyst.svt.plugin.model;

/**
 * Server side mirror of the client query type enumeration.
 *
 * <p>Ordinal order must match the client. A query type travels as its
 * ordinal in a var int.</p>
 */
public enum SvtQueryType {

    MODULE_STATE,
    CONFIG_HASH,
    INTEGRITY_HASH,
    STATS_SNAPSHOT,
    COMBAT_SUMMARY;

    /**
     * Resolves a query type by its enum name, case insensitive.
     *
     * @param name the enum constant name
     * @return the type, or null if not found
     */
    public static SvtQueryType byName(String name) {
        if (name == null) {
            return null;
        }
        try {
            return valueOf(name.toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
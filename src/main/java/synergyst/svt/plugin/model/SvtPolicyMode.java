package synergyst.svt.plugin.model;

/**
 * Server side mirror of the client policy mode enumeration.
 *
 * <p>Ordinal order must match the client. A mode travels as its
 * ordinal in a single byte within a policy manifest.</p>
 */
public enum SvtPolicyMode {

    /** Leave the module state unchanged. */
    ALLOW,

    /** Force the module off. */
    FORBID,

    /** Force the module on. */
    REQUIRE,

    /** Force the module off unless explicitly granted. */
    GRANT_ONLY;

    /**
     * Resolves a mode by its enum name, case insensitive.
     *
     * @param name the enum constant name
     * @return the mode, or null if not found
     */
    public static SvtPolicyMode byName(String name) {
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
     * Returns the boolean state this mode forces on a compliant client,
     * or null when the mode leaves the state unchanged.
     *
     * @return the forced state, or null
     */
    public Boolean forcedState() {
        return switch (this) {
            case FORBID, GRANT_ONLY -> Boolean.FALSE;
            case REQUIRE            -> Boolean.TRUE;
            case ALLOW              -> null;
        };
    }

    /**
     * Returns whether this mode actively changes the module state.
     *
     * @return whether the mode is anything other than {@link #ALLOW}
     */
    public boolean isEnforcing() {
        return this != ALLOW;
    }
}
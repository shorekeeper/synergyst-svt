package synergyst.svt.plugin.model;

/**
 * A single module enforcement rule within a server policy.
 *
 * @param module    the governed module
 * @param mode      the enforcement disposition
 * @param mandatory whether a client failure to satisfy the rule is
 *                  grounds to disconnect the client
 */
public record SvtPolicyRule(SvtModule module, SvtPolicyMode mode, boolean mandatory) {

    /**
     * Returns the boolean state this rule forces, or null when it
     * leaves the module unchanged.
     *
     * @return the forced state, or null
     */
    public Boolean forcedState() {
        return mode.forcedState();
    }

    /**
     * Returns whether this rule actively changes the module state.
     *
     * @return whether the mode enforces
     */
    public boolean isEnforcing() {
        return mode.isEnforcing();
    }
}
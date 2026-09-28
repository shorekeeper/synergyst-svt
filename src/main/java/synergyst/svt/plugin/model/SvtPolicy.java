package synergyst.svt.plugin.model;

import synergyst.svt.plugin.store.SvtPolicyStore;

import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * An immutable server policy loaded from the plugin configuration.
 *
 * <p>A policy declares the minimum acceptable mod version, a set of
 * module enforcement rules, and the configuration hash whitelist
 * options. It is constructed by {@link SvtPolicyStore} from a JSON file
 * that only a server operator can edit. No part of a policy originates
 * from the network.</p>
 */
public final class SvtPolicy {

    private final int policyVersion;
    private final String minModVersion;
    private final Map<SvtModule, SvtPolicyRule> rules;
    private final boolean requireConfigWhitelist;
    private final Set<String> approvedConfigHashes;

    /**
     * Constructs a policy.
     *
     * @param policyVersion          the policy version reported to clients
     * @param minModVersion          the minimum acceptable mod version
     * @param rules                  the module rules
     * @param requireConfigWhitelist whether a client config hash must be
     *                               on the approved list
     * @param approvedConfigHashes   the approved config hashes
     */
    public SvtPolicy(int policyVersion, String minModVersion,
                     Map<SvtModule, SvtPolicyRule> rules,
                     boolean requireConfigWhitelist,
                     Set<String> approvedConfigHashes) {
        this.policyVersion = policyVersion;
        this.minModVersion = minModVersion;
        this.rules = Collections.unmodifiableMap(new EnumMap<>(rules));
        this.requireConfigWhitelist = requireConfigWhitelist;
        this.approvedConfigHashes = Set.copyOf(approvedConfigHashes);
    }

    /**
     * Returns the policy version.
     *
     * @return the policy version
     */
    public int policyVersion() {
        return policyVersion;
    }

    /**
     * Returns the minimum acceptable mod version, possibly empty.
     *
     * @return the minimum mod version
     */
    public String minModVersion() {
        return minModVersion;
    }

    /**
     * Returns the rule for a module, or null if unmentioned.
     *
     * @param module the module
     * @return the rule, or null
     */
    public SvtPolicyRule ruleFor(SvtModule module) {
        return rules.get(module);
    }

    /**
     * Returns all rules.
     *
     * @return an unmodifiable list of rules
     */
    public List<SvtPolicyRule> rules() {
        return List.copyOf(rules.values());
    }

    /**
     * Returns whether config hash whitelisting is enabled.
     *
     * @return the whitelist requirement flag
     */
    public boolean requireConfigWhitelist() {
        return requireConfigWhitelist;
    }

    /**
     * Tests whether a config hash is approved.
     *
     * @param hash the client config hash
     * @return whether the hash is on the approved list
     */
    public boolean isConfigApproved(String hash) {
        return approvedConfigHashes.contains(hash);
    }

    /**
     * Returns the number of rules that actively change a module state.
     *
     * @return the enforcing rule count
     */
    public int enforcingCount() {
        int count = 0;
        for (SvtPolicyRule rule : rules.values()) {
            if (rule.isEnforcing()) {
                count++;
            }
        }
        return count;
    }
}
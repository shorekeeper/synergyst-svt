package synergyst.svt.plugin.store;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import synergyst.svt.plugin.model.SvtPolicy;
import synergyst.svt.plugin.model.SvtModule;
import synergyst.svt.plugin.model.SvtPolicyMode;
import synergyst.svt.plugin.model.SvtPolicyRule;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Loads and hot reloads the server policy from a JSON file.
 *
 * <h2>File format</h2>
 * <pre>{@code
 *   {
 *     "policyVersion": 1,
 *     "minModVersion": "v2.1.16",
 *     "requireConfigWhitelist": false,
 *     "approvedConfigHashes": [],
 *     "rules": {
 *       "FAST_ATTACK_PLACE": { "mode": "ALLOW",  "mandatory": false },
 *       "BOT_TRAINING":      { "mode": "FORBID", "mandatory": true }
 *     }
 *   }
 * }</pre>
 *
 * <h2>Validation</h2>
 * Unknown module names and unknown mode names are skipped with a
 * warning rather than aborting the load. A missing file causes a
 * default permissive policy to be written and used.
 */
public final class SvtPolicyStore {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private final Path file;
    private final Logger logger;
    private volatile SvtPolicy active;

    /** JSON shape of a single rule. */
    private static final class RuleJson {
        String mode;
        boolean mandatory;
    }

    /** JSON shape of the policy file. */
    private static final class PolicyJson {
        int policyVersion = 1;
        String minModVersion = "";
        boolean requireConfigWhitelist = false;
        java.util.List<String> approvedConfigHashes = new java.util.ArrayList<>();
        Map<String, RuleJson> rules = new LinkedHashMap<>();
    }

    /**
     * Creates a policy store bound to a file path.
     *
     * @param file   the policy file path
     * @param logger the plugin logger
     */
    public SvtPolicyStore(Path file, Logger logger) {
        this.file = file;
        this.logger = logger;
    }

    /**
     * Loads the policy from disk, writing a default file if none
     * exists.
     */
    public void load() {
        try {
            if (!Files.exists(file)) {
                writeDefault();
            }
            String json = Files.readString(file, StandardCharsets.UTF_8);
            PolicyJson parsed = GSON.fromJson(json, PolicyJson.class);
            if (parsed == null) {
                parsed = new PolicyJson();
            }
            active = build(parsed);
            logger.info("Loaded SVT policy v" + active.policyVersion()
                    + " with " + active.enforcingCount() + " enforcing rules");
        } catch (Exception e) {
            logger.severe("Failed to load SVT policy: " + e.getMessage());
            active = build(new PolicyJson());
        }
    }

    private SvtPolicy build(PolicyJson json) {
        Map<SvtModule, SvtPolicyRule> rules = new EnumMap<>(SvtModule.class);
        for (Map.Entry<String, RuleJson> entry : json.rules.entrySet()) {
            SvtModule module = SvtModule.byName(entry.getKey());
            if (module == null) {
                logger.warning("Unknown module in policy: " + entry.getKey());
                continue;
            }
            RuleJson ruleJson = entry.getValue();
            SvtPolicyMode mode = SvtPolicyMode.byName(ruleJson.mode);
            if (mode == null) {
                logger.warning("Unknown mode for " + entry.getKey() + ": " + ruleJson.mode);
                continue;
            }
            rules.put(module, new SvtPolicyRule(module, mode, ruleJson.mandatory));
        }
        return new SvtPolicy(
                json.policyVersion,
                json.minModVersion == null ? "" : json.minModVersion,
                rules,
                json.requireConfigWhitelist,
                Set.copyOf(json.approvedConfigHashes));
    }

    private void writeDefault() throws IOException {
        PolicyJson def = new PolicyJson();
        def.policyVersion = 1;
        def.minModVersion = "";
        RuleJson botRule = new RuleJson();
        botRule.mode = SvtPolicyMode.FORBID.name();
        botRule.mandatory = true;
        def.rules.put(SvtModule.BOT_TRAINING.name(), botRule);
        Files.createDirectories(file.getParent());
        Files.writeString(file, GSON.toJson(def), StandardCharsets.UTF_8);
        logger.info("Wrote default SVT policy to " + file);
    }

    /**
     * Returns the active policy.
     *
     * @return the current policy
     */
    public SvtPolicy policy() {
        return active;
    }
}
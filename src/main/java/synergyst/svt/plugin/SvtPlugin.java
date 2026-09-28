package synergyst.svt.plugin;

import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.plugin.java.JavaPlugin;
import synergyst.svt.plugin.command.SvtCommand;
import synergyst.svt.plugin.model.SvtPeer;
import synergyst.svt.plugin.net.SvtChallengeManager;
import synergyst.svt.plugin.net.SvtChannelListener;
import synergyst.svt.plugin.net.SvtMessenger;
import synergyst.svt.plugin.net.SvtPeerRegistry;
import synergyst.svt.plugin.protocol.SvtProtocol;
import synergyst.svt.plugin.store.SvtAuditLog;
import synergyst.svt.plugin.store.SvtBlocklist;
import synergyst.svt.plugin.store.SvtPolicyStore;

import java.nio.file.Path;

/**
 * Main plugin entry point for the server side Skill Verification Token
 * subsystem.
 *
 * <h2>Responsibilities on enable</h2>
 * <ul>
 *   <li>Load the policy, blocklist, and prepare the audit log.</li>
 *   <li>Register the plugin message channel for inbound and outbound
 *       traffic.</li>
 *   <li>Register the administration command and the quit listener.</li>
 * </ul>
 *
 * <h2>Client interaction</h2>
 * The client mod initiates the handshake. This plugin responds to
 * presence announcements with challenges, verifies handshakes, applies
 * policy, relays peer presence, and answers administrator driven
 * inspection. No behaviour is initiated by the plugin toward a client
 * that has not first announced itself.
 */
public final class SvtPlugin extends JavaPlugin implements Listener {

    private SvtMessenger messenger;
    private SvtPeerRegistry registry;
    private SvtChallengeManager challenges;
    private SvtPolicyStore policyStore;
    private SvtBlocklist blocklist;
    private SvtAuditLog audit;
    private SvtChannelListener listener;

    @Override
    public void onEnable() {
        Path dir = getDataFolder().toPath();

        this.policyStore = new SvtPolicyStore(dir.resolve("policy.json"), getLogger());
        this.blocklist = new SvtBlocklist(dir.resolve("blocklist.txt"), getLogger());
        this.audit = new SvtAuditLog(dir.resolve("audit.jsonl"), getLogger());
        this.registry = new SvtPeerRegistry();
        this.challenges = new SvtChallengeManager();
        this.messenger = new SvtMessenger(this);

        policyStore.load();
        blocklist.load();

        this.listener = new SvtChannelListener(this);
        getServer().getMessenger().registerOutgoingPluginChannel(this, SvtProtocol.CHANNEL);
        getServer().getMessenger().registerIncomingPluginChannel(this, SvtProtocol.CHANNEL, listener);

        var command = new SvtCommand(this);
        getCommand("svt").setExecutor(command);
        getCommand("svt").setTabCompleter(command);

        getServer().getPluginManager().registerEvents(this, this);

        getLogger().info("SVT server plugin enabled, protocol v" + SvtProtocol.VERSION);
    }

    @Override
    public void onDisable() {
        getServer().getMessenger().unregisterOutgoingPluginChannel(this);
        getServer().getMessenger().unregisterIncomingPluginChannel(this);
        getLogger().info("SVT server plugin disabled");
    }

    /**
     * Removes a departing player from the registry and broadcasts a
     * peer left announcement to the remaining verified peers.
     *
     * @param event the quit event
     */
    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        var uuid = event.getPlayer().getUniqueId();
        challenges.clear(uuid);
        SvtPeer removed = registry.remove(uuid);
        if (removed == null || removed.isHandshakeOnly()) {
            return;
        }
        for (SvtPeer other : registry.all()) {
            org.bukkit.entity.Player otherPlayer =
                    getServer().getPlayer(other.uuid());
            if (otherPlayer != null) {
                messenger.sendPeerLeft(otherPlayer, uuid);
            }
        }
    }

    /* ═══════════════════ Accessors ═══════════════════ */

    public SvtMessenger messenger() {
        return messenger;
    }

    public SvtPeerRegistry registry() {
        return registry;
    }

    public SvtChallengeManager challenges() {
        return challenges;
    }

    public SvtPolicyStore policyStore() {
        return policyStore;
    }

    public SvtBlocklist blocklist() {
        return blocklist;
    }

    public SvtAuditLog audit() {
        return audit;
    }

    public SvtChannelListener listener() {
        return listener;
    }
}
package synergyst.svt.plugin.command;

import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;
import synergyst.svt.plugin.SvtPlugin;
import synergyst.svt.plugin.model.SvtPolicy;
import synergyst.svt.plugin.model.SvtModule;
import synergyst.svt.plugin.model.SvtPeer;
import synergyst.svt.plugin.model.SvtQueryType;
import synergyst.svt.plugin.protocol.SvtProtocol;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Administrative command tree for SVT.
 *
 * <h2>Subcommands</h2>
 * <ul>
 *   <li>{@code list} lists verified peers with version and module counts.</li>
 *   <li>{@code inspect <player>} shows a peer full manifest summary.</li>
 *   <li>{@code query <player> <type>} sends an on demand inspection request.</li>
 *   <li>{@code grant <player> <module>} grants a restricted module.</li>
 *   <li>{@code block <player>} blocks a peer public key.</li>
 *   <li>{@code unblock <keyHash>} removes a key from the blocklist.</li>
 *   <li>{@code kick <player> [reason]} disconnects a player.</li>
 *   <li>{@code msg <player> <severity> <text>} sends an admin notice.</li>
 *   <li>{@code policy reload} reloads the policy file.</li>
 *   <li>{@code audit [n]} prints the last audit lines.</li>
 * </ul>
 */
public final class SvtCommand implements CommandExecutor, TabCompleter {

    private final SvtPlugin plugin;

    public SvtCommand(SvtPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command,
                             String label, String[] args) {
        if (!sender.hasPermission("svt.admin")) {
            sender.sendMessage("You lack the svt.admin permission.");
            return true;
        }
        if (args.length == 0) {
            sender.sendMessage("Usage: /svt <list|inspect|query|grant|block|"
                    + "unblock|kick|msg|policy|audit>");
            return true;
        }
        switch (args[0].toLowerCase()) {
            case "list" -> doList(sender);
            case "inspect" -> doInspect(sender, args);
            case "query" -> doQuery(sender, args);
            case "grant" -> doGrant(sender, args);
            case "block" -> doBlock(sender, args);
            case "unblock" -> doUnblock(sender, args);
            case "kick" -> doKick(sender, args);
            case "msg" -> doMsg(sender, args);
            case "policy" -> doPolicy(sender, args);
            case "audit" -> doAudit(sender, args);
            default -> sender.sendMessage("Unknown subcommand: " + args[0]);
        }
        return true;
    }

    private void doList(CommandSender sender) {
        var peers = plugin.registry().all();
        sender.sendMessage("SVT verified peers: " + peers.size());
        for (SvtPeer peer : peers) {
            int modules = 0;
            for (long word : peer.moduleBits()) {
                modules += Long.bitCount(word);
            }
            sender.sendMessage("  " + peer.name() + "  v" + peer.modVersion()
                    + "  fp " + peer.fingerprint() + "  modules " + modules
                    + (peer.isHandshakeOnly() ? "  [handshake only]" : ""));
        }
    }

    private void doInspect(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage("Usage: /svt inspect <player>");
            return;
        }
        Player target = Bukkit.getPlayer(args[1]);
        if (target == null) {
            sender.sendMessage("Player not online: " + args[1]);
            return;
        }
        SvtPeer peer = plugin.registry().get(target.getUniqueId());
        if (peer == null) {
            sender.sendMessage(args[1] + " is not a verified mod user.");
            return;
        }
        sender.sendMessage("SVT inspect " + peer.name());
        sender.sendMessage("  version " + peer.modVersion());
        sender.sendMessage("  fingerprint " + peer.fingerprint());
        sender.sendMessage("  keyHash " + peer.keyHash());
        sender.sendMessage("  configHash " + peer.configHash());
        StringBuilder active = new StringBuilder();
        for (SvtModule module : SvtModule.values()) {
            if (module.isSet(peer.moduleBits())) {
                active.append(module.name()).append(' ');
            }
        }
        sender.sendMessage("  active: " + (active.length() == 0 ? "none" : active));
    }

    private void doQuery(CommandSender sender, String[] args) {
        if (args.length < 3) {
            sender.sendMessage("Usage: /svt query <player> "
                    + "<MODULE_STATE|CONFIG_HASH|INTEGRITY_HASH|"
                    + "STATS_SNAPSHOT|COMBAT_SUMMARY>");
            return;
        }
        Player target = Bukkit.getPlayer(args[1]);
        if (target == null) {
            sender.sendMessage("Player not online: " + args[1]);
            return;
        }
        SvtQueryType type = SvtQueryType.byName(args[2]);
        if (type == null) {
            sender.sendMessage("Unknown query type: " + args[2]);
            return;
        }
        if (sender instanceof Player p) {
            plugin.listener().registerPendingQuery(target.getUniqueId(), p.getUniqueId());
        }
        plugin.messenger().sendQueryRequest(target, type);
        sender.sendMessage("Query " + type.name() + " sent to " + target.getName());
    }

    private void doGrant(CommandSender sender, String[] args) {
        if (args.length < 3) {
            sender.sendMessage("Usage: /svt grant <player> <module>");
            return;
        }
        Player target = Bukkit.getPlayer(args[1]);
        if (target == null) {
            sender.sendMessage("Player not online: " + args[1]);
            return;
        }
        SvtModule module = SvtModule.byName(args[2]);
        if (module == null) {
            sender.sendMessage("Unknown module: " + args[2]);
            return;
        }
        plugin.messenger().sendFeatureGrant(target, module, true);
        sender.sendMessage("Granted " + module.name() + " to " + target.getName());
    }

    private void doBlock(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage("Usage: /svt block <player>");
            return;
        }
        Player target = Bukkit.getPlayer(args[1]);
        if (target == null) {
            sender.sendMessage("Player not online: " + args[1]);
            return;
        }
        SvtPeer peer = plugin.registry().get(target.getUniqueId());
        if (peer == null) {
            sender.sendMessage(args[1] + " is not a verified mod user.");
            return;
        }
        if (plugin.blocklist().add(peer.keyHash())) {
            sender.sendMessage("Blocked key " + peer.fingerprint()
                    + " (" + target.getName() + ")");
            target.kickPlayer("Your mod identity has been blocked.");
        } else {
            sender.sendMessage("Key already blocked.");
        }
    }

    private void doUnblock(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage("Usage: /svt unblock <keyHash>");
            return;
        }
        if (plugin.blocklist().remove(args[1])) {
            sender.sendMessage("Unblocked " + args[1]);
        } else {
            sender.sendMessage("Key not on the blocklist.");
        }
    }

    private void doKick(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage("Usage: /svt kick <player> [reason]");
            return;
        }
        Player target = Bukkit.getPlayer(args[1]);
        if (target == null) {
            sender.sendMessage("Player not online: " + args[1]);
            return;
        }
        String reason = args.length > 2
                ? String.join(" ", Arrays.copyOfRange(args, 2, args.length))
                : "Disconnected by SVT administration.";
        target.kickPlayer(reason);
        sender.sendMessage("Kicked " + target.getName());
    }

    private void doMsg(CommandSender sender, String[] args) {
        if (args.length < 4) {
            sender.sendMessage("Usage: /svt msg <player> <info|warn|error> <text>");
            return;
        }
        Player target = Bukkit.getPlayer(args[1]);
        if (target == null) {
            sender.sendMessage("Player not online: " + args[1]);
            return;
        }
        if (!plugin.registry().contains(target.getUniqueId())) {
            sender.sendMessage(args[1] + " is not a verified mod user.");
            return;
        }
        byte severity = switch (args[2].toLowerCase()) {
            case "warn"  -> SvtProtocol.SEVERITY_WARN;
            case "error" -> SvtProtocol.SEVERITY_ERROR;
            default      -> SvtProtocol.SEVERITY_INFO;
        };
        String text = String.join(" ", Arrays.copyOfRange(args, 3, args.length));
        plugin.messenger().sendAdminMessage(target, severity, text);
        sender.sendMessage("Sent notice to " + target.getName());
    }

    private void doPolicy(CommandSender sender, String[] args) {
        if (args.length < 2 || !args[1].equalsIgnoreCase("reload")) {
            sender.sendMessage("Usage: /svt policy reload");
            return;
        }
        plugin.policyStore().load();
        plugin.blocklist().load();
        SvtPolicy policy = plugin.policyStore().policy();
        for (Player online : Bukkit.getOnlinePlayers()) {
            if (plugin.registry().contains(online.getUniqueId())) {
                plugin.messenger().sendPolicy(online, policy);
            }
        }
        sender.sendMessage("Reloaded policy v" + policy.policyVersion()
                + " and pushed to verified peers.");
    }

    private void doAudit(CommandSender sender, String[] args) {
        int n = 10;
        if (args.length > 1) {
            try {
                n = Math.max(1, Math.min(100, Integer.parseInt(args[1])));
            } catch (NumberFormatException ignored) {
                // keep default
            }
        }
        List<String> lines = plugin.audit().tail(n);
        sender.sendMessage("SVT audit (last " + lines.size() + "):");
        for (String line : lines) {
            sender.sendMessage("  " + line);
        }
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command,
                                      String alias, String[] args) {
        List<String> out = new ArrayList<>();
        if (args.length == 1) {
            out.addAll(Arrays.asList("list", "inspect", "query", "grant",
                    "block", "unblock", "kick", "msg", "policy", "audit"));
        } else if (args.length == 2) {
            String sub = args[0].toLowerCase();
            if (sub.equals("inspect") || sub.equals("query") || sub.equals("grant")
                    || sub.equals("block") || sub.equals("kick") || sub.equals("msg")) {
                for (Player p : Bukkit.getOnlinePlayers()) {
                    out.add(p.getName());
                }
            } else if (sub.equals("policy")) {
                out.add("reload");
            }
        } else if (args.length == 3) {
            String sub = args[0].toLowerCase();
            if (sub.equals("query")) {
                for (SvtQueryType type : SvtQueryType.values()) {
                    out.add(type.name());
                }
            } else if (sub.equals("grant")) {
                for (SvtModule module : SvtModule.values()) {
                    out.add(module.name());
                }
            } else if (sub.equals("msg")) {
                out.addAll(Arrays.asList("info", "warn", "error"));
            }
        }
        return out;
    }
}
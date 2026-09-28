package synergyst.svt.plugin.net;

import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import synergyst.svt.plugin.model.SvtPolicy;
import synergyst.svt.plugin.model.SvtModule;
import synergyst.svt.plugin.model.SvtPeer;
import synergyst.svt.plugin.model.SvtPolicyRule;
import synergyst.svt.plugin.model.SvtQueryType;
import synergyst.svt.plugin.protocol.SvtByteBuf;
import synergyst.svt.plugin.protocol.SvtProtocol;

import java.util.UUID;

/**
 * Builds and sends server to client SVT packets.
 *
 * <p>All packets are constructed with {@link SvtByteBuf} in the
 * Minecraft wire format the client expects and delivered through the
 * Bukkit plugin messaging system.</p>
 */
public final class SvtMessenger {

    private final Plugin plugin;

    /**
     * Creates a messenger bound to the owning plugin.
     *
     * @param plugin the plugin instance
     */
    public SvtMessenger(Plugin plugin) {
        this.plugin = plugin;
    }

    private void send(Player player, byte[] payload) {
        player.sendPluginMessage(plugin, SvtProtocol.CHANNEL, payload);
    }

    /**
     * Sends a challenge nonce to a player.
     *
     * @param player the target player
     * @param nonce  the nonce bytes
     */
    public void sendChallenge(Player player, byte[] nonce) {
        byte[] payload = SvtByteBuf.writer()
                .writeByte(SvtProtocol.S2C_SERVER_CHALLENGE)
                .writeByteArray(nonce)
                .writeVarInt(SvtProtocol.VERSION)
                .toBytes();
        send(player, payload);
    }

    /**
     * Sends a handshake rejection.
     *
     * @param player  the target player
     * @param reason  the reason code
     * @param message a short explanatory message
     */
    public void sendReject(Player player, byte reason, String message) {
        byte[] payload = SvtByteBuf.writer()
                .writeByte(SvtProtocol.S2C_PROTOCOL_REJECT)
                .writeByte(reason)
                .writeString(message == null ? "" : message)
                .toBytes();
        send(player, payload);
    }

    /**
     * Sends a policy manifest.
     *
     * @param player the target player
     * @param policy the policy to encode
     */
    public void sendPolicy(Player player, SvtPolicy policy) {
        SvtByteBuf buf = SvtByteBuf.writer()
                .writeByte(SvtProtocol.S2C_POLICY_MANIFEST)
                .writeVarInt(policy.policyVersion());

        var rules = policy.rules();
        buf.writeVarInt(rules.size());
        for (SvtPolicyRule rule : rules) {
            buf.writeVarInt(rule.module().ordinal());
            buf.writeByte(rule.mode().ordinal());
            buf.writeByte(rule.mandatory() ? 1 : 0);
        }
        send(player, buf.toBytes());
    }

    /**
     * Sends an administrative notice.
     *
     * @param player   the target player
     * @param severity the severity byte
     * @param message  the message text
     */
    public void sendAdminMessage(Player player, byte severity, String message) {
        byte[] payload = SvtByteBuf.writer()
                .writeByte(SvtProtocol.S2C_ADMIN_MESSAGE)
                .writeByte(severity)
                .writeString(message)
                .toBytes();
        send(player, payload);
    }

    /**
     * Sends an inspection request.
     *
     * @param player the target player
     * @param type   the query type
     */
    public void sendQueryRequest(Player player, SvtQueryType type) {
        byte[] payload = SvtByteBuf.writer()
                .writeByte(SvtProtocol.S2C_QUERY_REQUEST)
                .writeVarInt(type.ordinal())
                .toBytes();
        send(player, payload);
    }

    /**
     * Sends a feature grant or revocation.
     *
     * @param player  the target player
     * @param module  the module
     * @param granted whether the module is granted
     */
    public void sendFeatureGrant(Player player, SvtModule module, boolean granted) {
        byte[] payload = SvtByteBuf.writer()
                .writeByte(SvtProtocol.S2C_FEATURE_GRANT)
                .writeVarInt(module.ordinal())
                .writeByte(granted ? 1 : 0)
                .toBytes();
        send(player, payload);
    }

    /**
     * Sends a peer present announcement.
     *
     * @param player the target player
     * @param peer   the peer to announce
     */
    public void sendPeerPresent(Player player, SvtPeer peer) {
        byte[] payload = SvtByteBuf.writer()
                .writeByte(SvtProtocol.S2C_PEER_PRESENT)
                .writeUuid(peer.uuid())
                .writeString(peer.name())
                .writeString(peer.modVersion())
                .writeByte(peer.capabilities())
                .toBytes();
        send(player, payload);
    }

    /**
     * Sends a peer left announcement.
     *
     * @param player the target player
     * @param uuid   the departed peer UUID
     */
    public void sendPeerLeft(Player player, UUID uuid) {
        byte[] payload = SvtByteBuf.writer()
                .writeByte(SvtProtocol.S2C_PEER_LEFT)
                .writeUuid(uuid)
                .toBytes();
        send(player, payload);
    }
}
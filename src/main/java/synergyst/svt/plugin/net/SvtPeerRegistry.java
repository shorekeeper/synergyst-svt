package synergyst.svt.plugin.net;

import synergyst.svt.plugin.model.SvtPeer;

import java.util.Collection;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In memory registry of verified peers keyed by account UUID.
 */
public final class SvtPeerRegistry {

    private final Map<UUID, SvtPeer> peers = new ConcurrentHashMap<>();

    /**
     * Stores or replaces a peer.
     *
     * @param peer the peer state
     */
    public void put(SvtPeer peer) {
        peers.put(peer.uuid(), peer);
    }

    /**
     * Removes a peer.
     *
     * @param uuid the account UUID
     * @return the removed peer, or null
     */
    public SvtPeer remove(UUID uuid) {
        return peers.remove(uuid);
    }

    /**
     * Returns a peer by UUID.
     *
     * @param uuid the account UUID
     * @return the peer, or null
     */
    public SvtPeer get(UUID uuid) {
        return peers.get(uuid);
    }

    /**
     * Returns whether the account is a verified peer.
     *
     * @param uuid the account UUID
     * @return whether the peer is registered
     */
    public boolean contains(UUID uuid) {
        return peers.containsKey(uuid);
    }

    /**
     * Returns all verified peers.
     *
     * @return an immutable view of the peers
     */
    public Collection<SvtPeer> all() {
        return Map.copyOf(peers).values();
    }

    /**
     * Returns the number of verified peers.
     *
     * @return the peer count
     */
    public int size() {
        return peers.size();
    }
}
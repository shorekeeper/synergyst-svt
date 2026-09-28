package synergyst.svt.plugin.store;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Persistent set of revoked public key hashes.
 *
 * <p>A blocked entry is the full SHA-256 hash of a client public key.
 * Blocking a key rejects any client presenting that identity regardless
 * of the account it uses, so a name change does not evade the block. A
 * blocked user must generate a new identity to reconnect, and that new
 * identity can be caught again through behavioural corroboration.</p>
 *
 * <h2>Storage</h2>
 * One key hash per line in a plain text file. Blank lines and lines
 * beginning with a hash sign are ignored.
 */
public final class SvtBlocklist {

    private final Path file;
    private final Logger logger;
    private final Set<String> blocked = ConcurrentHashMap.newKeySet();

    /**
     * Creates a blocklist bound to a file path.
     *
     * @param file   the blocklist file path
     * @param logger the plugin logger
     */
    public SvtBlocklist(Path file, Logger logger) {
        this.file = file;
        this.logger = logger;
    }

    /**
     * Loads the blocklist from disk, creating an empty file if none
     * exists.
     */
    public void load() {
        try {
            if (!Files.exists(file)) {
                Files.createDirectories(file.getParent());
                Files.writeString(file, "# One public key hash per line\n",
                        StandardCharsets.UTF_8);
            }
            blocked.clear();
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                blocked.add(trimmed.toLowerCase());
            }
            logger.info("Loaded " + blocked.size() + " SVT blocklist entries");
        } catch (Exception e) {
            logger.severe("Failed to load SVT blocklist: " + e.getMessage());
        }
    }

    /**
     * Tests whether a key hash is blocked.
     *
     * @param keyHash the full key hash
     * @return whether the hash is on the blocklist
     */
    public boolean isBlocked(String keyHash) {
        return keyHash != null && blocked.contains(keyHash.toLowerCase());
    }

    /**
     * Adds a key hash to the blocklist and appends it to the file.
     *
     * @param keyHash the full key hash
     * @return whether the hash was newly added
     */
    public boolean add(String keyHash) {
        if (keyHash == null) {
            return false;
        }
        String normalized = keyHash.toLowerCase();
        if (!blocked.add(normalized)) {
            return false;
        }
        try {
            Files.writeString(file, normalized + "\n", StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            logger.warning("Failed to persist blocklist entry: " + e.getMessage());
        }
        return true;
    }

    /**
     * Removes a key hash from the blocklist and rewrites the file.
     *
     * @param keyHash the full key hash
     * @return whether the hash was present and removed
     */
    public boolean remove(String keyHash) {
        if (keyHash == null) {
            return false;
        }
        if (!blocked.remove(keyHash.toLowerCase())) {
            return false;
        }
        rewrite();
        return true;
    }

    private void rewrite() {
        try {
            StringBuilder sb = new StringBuilder("# One public key hash per line\n");
            for (String entry : blocked) {
                sb.append(entry).append('\n');
            }
            Files.writeString(file, sb.toString(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException e) {
            logger.warning("Failed to rewrite blocklist: " + e.getMessage());
        }
    }

    /**
     * Returns the number of blocked entries.
     *
     * @return the block count
     */
    public int size() {
        return blocked.size();
    }
}
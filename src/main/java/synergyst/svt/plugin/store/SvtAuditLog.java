package synergyst.svt.plugin.store;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.logging.Logger;

/**
 * Append only audit log of handshake verdicts in JSON lines format.
 *
 * <p>Each verified or rejected handshake produces one line. The format
 * is suitable for ingestion by an external log processor or dashboard.
 * Writes are synchronized so concurrent handshakes do not interleave
 * within a line.</p>
 */
public final class SvtAuditLog {

    private static final Gson GSON = new Gson();

    private final Path file;
    private final Logger logger;
    private final Object lock = new Object();

    /**
     * Creates an audit log bound to a file path.
     *
     * @param file   the audit file path
     * @param logger the plugin logger
     */
    public SvtAuditLog(Path file, Logger logger) {
        this.file = file;
        this.logger = logger;
    }

    /**
     * Writes one audit entry.
     *
     * @param uuid            the account UUID
     * @param name            the account name
     * @param keyFingerprint  the short key fingerprint
     * @param modVersion      the reported mod version
     * @param protocolVersion the reported protocol version
     * @param moduleCount     the number of active modules
     * @param configHash      the reported config hash
     * @param verdict         the handshake verdict text
     */
    public void record(String uuid, String name, String keyFingerprint,
                       String modVersion, int protocolVersion,
                       int moduleCount, String configHash, String verdict) {
        JsonObject obj = new JsonObject();
        obj.addProperty("ts", System.currentTimeMillis());
        obj.addProperty("uuid", uuid);
        obj.addProperty("name", name);
        obj.addProperty("keyFingerprint", keyFingerprint);
        obj.addProperty("modVersion", modVersion);
        obj.addProperty("protocolVersion", protocolVersion);
        obj.addProperty("moduleCount", moduleCount);
        obj.addProperty("configHash", configHash);
        obj.addProperty("verdict", verdict);

        String line = GSON.toJson(obj) + "\n";
        synchronized (lock) {
            try {
                Files.createDirectories(file.getParent());
                Files.writeString(file, line, StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (IOException e) {
                logger.warning("Failed to write audit entry: " + e.getMessage());
            }
        }
    }

    /**
     * Reads the last n lines of the audit log.
     *
     * @param n the maximum number of lines
     * @return the tail lines, oldest first, or an empty list on failure
     */
    public java.util.List<String> tail(int n) {
        try {
            if (!Files.exists(file)) {
                return java.util.List.of();
            }
            java.util.List<String> all = Files.readAllLines(file, StandardCharsets.UTF_8);
            int from = Math.max(0, all.size() - n);
            return all.subList(from, all.size());
        } catch (IOException e) {
            return java.util.List.of();
        }
    }
}
package synergyst.svt.plugin.crypto;

/**
 * Lenient mod version comparison for the version gate.
 *
 * <p>Version strings are compared by their numeric components. A
 * leading letter such as the {@code v} prefix is ignored, and trailing
 * non numeric qualifiers such as a release candidate suffix are not
 * considered. The comparison walks numeric groups left to right. A
 * missing group is treated as zero.</p>
 */
public final class SvtVersion {

    private SvtVersion() {
        throw new AssertionError("Utility class");
    }

    /**
     * Tests whether a client version satisfies a minimum requirement.
     *
     * @param client the client mod version
     * @param minimum the required minimum version
     * @return whether the client version is greater than or equal to
     *         the minimum
     */
    public static boolean satisfies(String client, String minimum) {
        if (minimum == null || minimum.isBlank()) {
            return true;
        }
        int[] c = parse(client);
        int[] m = parse(minimum);
        int len = Math.max(c.length, m.length);
        for (int i = 0; i < len; i++) {
            int cv = i < c.length ? c[i] : 0;
            int mv = i < m.length ? m[i] : 0;
            if (cv != mv) {
                return cv > mv;
            }
        }
        return true;
    }

    private static int[] parse(String version) {
        if (version == null) {
            return new int[0];
        }
        String[] parts = version.replaceAll("[^0-9.]", " ").trim().split("[.\\s]+");
        int[] out = new int[parts.length];
        int count = 0;
        for (String part : parts) {
            if (part.isEmpty()) {
                continue;
            }
            try {
                out[count++] = Integer.parseInt(part);
            } catch (NumberFormatException ignored) {
                // skip non numeric groups
            }
        }
        int[] trimmed = new int[count];
        System.arraycopy(out, 0, trimmed, 0, count);
        return trimmed;
    }
}
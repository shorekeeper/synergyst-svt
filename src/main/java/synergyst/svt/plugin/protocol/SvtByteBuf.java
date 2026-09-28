package synergyst.svt.plugin.protocol;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Reader and writer for the Minecraft {@code PacketByteBuf} wire format
 * over plain byte arrays.
 *
 * <p>Bukkit plugin messaging delivers a raw byte array whose content is
 * exactly the buffer the client wrote with a {@code PacketByteBuf}. The
 * Guava {@code ByteArrayDataInput} used by many plugins is incompatible
 * with that format because it encodes integers and strings differently.
 * This class implements the correct variable length integer, length
 * prefixed string, length prefixed byte array, long, and UUID encodings
 * so that the plugin can decode client packets and encode replies the
 * client understands.</p>
 *
 * <h2>Hostile input</h2>
 * The read side treats the source array as hostile. Every read checks
 * bounds and throws {@link SvtDecodeException} on underflow. Length
 * prefixed reads accept an explicit maximum and reject a declared
 * length that exceeds it before allocating, so a malicious client
 * cannot force an oversized allocation.
 */
public final class SvtByteBuf {

    /**
     * Thrown when a read fails a bounds or length check.
     */
    public static final class SvtDecodeException extends RuntimeException {
        public SvtDecodeException(String message) {
            super(message);
        }
    }

    /* ═══════════════════ Writer ═══════════════════ */

    private final ByteArrayOutputStream out;

    private SvtByteBuf(ByteArrayOutputStream out) {
        this.out = out;
        this.data = null;
        this.pos = 0;
    }

    /**
     * Creates a writer backed by a growable byte buffer.
     *
     * @return a new writer
     */
    public static SvtByteBuf writer() {
        return new SvtByteBuf(new ByteArrayOutputStream(64));
    }

    /**
     * Writes a single byte.
     *
     * @param value the byte value
     * @return this writer
     */
    public SvtByteBuf writeByte(int value) {
        out.write(value & 0xFF);
        return this;
    }

    /**
     * Writes a variable length integer in the Minecraft encoding.
     *
     * @param value the value
     * @return this writer
     */
    public SvtByteBuf writeVarInt(int value) {
        while ((value & ~0x7F) != 0) {
            out.write((value & 0x7F) | 0x80);
            value >>>= 7;
        }
        out.write(value);
        return this;
    }

    /**
     * Writes a signed 64 bit big endian long.
     *
     * @param value the value
     * @return this writer
     */
    public SvtByteBuf writeLong(long value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            out.write((int) ((value >>> shift) & 0xFF));
        }
        return this;
    }

    /**
     * Writes a length prefixed UTF-8 string.
     *
     * @param value the string
     * @return this writer
     */
    public SvtByteBuf writeString(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        writeVarInt(bytes.length);
        out.write(bytes, 0, bytes.length);
        return this;
    }

    /**
     * Writes a length prefixed byte array.
     *
     * @param value the bytes
     * @return this writer
     */
    public SvtByteBuf writeByteArray(byte[] value) {
        writeVarInt(value.length);
        out.write(value, 0, value.length);
        return this;
    }

    /**
     * Writes a UUID as two longs, most significant first.
     *
     * @param uuid the UUID
     * @return this writer
     */
    public SvtByteBuf writeUuid(java.util.UUID uuid) {
        writeLong(uuid.getMostSignificantBits());
        writeLong(uuid.getLeastSignificantBits());
        return this;
    }

    /**
     * Writes a long array as a var int count followed by the values,
     * matching the client custom codec.
     *
     * @param values the values
     * @return this writer
     */
    public SvtByteBuf writeLongArray(long[] values) {
        writeVarInt(values.length);
        for (long value : values) {
            writeLong(value);
        }
        return this;
    }

    /**
     * Returns the accumulated bytes.
     *
     * @return the written byte array
     */
    public byte[] toBytes() {
        return out.toByteArray();
    }

    /* ═══════════════════ Reader ═══════════════════ */

    private final byte[] data;
    private int pos;

    private SvtByteBuf(byte[] data) {
        this.out = null;
        this.data = data;
        this.pos = 0;
    }

    /**
     * Creates a reader over the given byte array.
     *
     * @param data the source bytes
     * @return a new reader
     */
    public static SvtByteBuf reader(byte[] data) {
        return new SvtByteBuf(data);
    }

    private void require(int count) {
        if (pos + count > data.length) {
            throw new SvtDecodeException("buffer underflow");
        }
    }

    /**
     * Reads a single byte.
     *
     * @return the byte value
     */
    public byte readByte() {
        require(1);
        return data[pos++];
    }

    /**
     * Reads a variable length integer.
     *
     * @return the decoded value
     */
    public int readVarInt() {
        int value = 0;
        int position = 0;
        byte b;
        do {
            require(1);
            b = data[pos++];
            value |= (b & 0x7F) << position;
            position += 7;
            if (position >= 35) {
                throw new SvtDecodeException("var int too long");
            }
        } while ((b & 0x80) != 0);
        return value;
    }

    /**
     * Reads a signed 64 bit big endian long.
     *
     * @return the value
     */
    public long readLong() {
        require(8);
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (data[pos++] & 0xFFL);
        }
        return value;
    }

    /**
     * Reads a length prefixed UTF-8 string, rejecting a declared
     * length beyond the given maximum.
     *
     * @param maxLen the maximum byte length
     * @return the decoded string
     */
    public String readString(int maxLen) {
        int len = readVarInt();
        if (len < 0 || len > maxLen) {
            throw new SvtDecodeException("string length " + len + " exceeds " + maxLen);
        }
        require(len);
        String value = new String(data, pos, len, StandardCharsets.UTF_8);
        pos += len;
        return value;
    }

    /**
     * Reads a length prefixed byte array, rejecting a declared length
     * beyond the given maximum.
     *
     * @param maxLen the maximum length
     * @return the decoded bytes
     */
    public byte[] readByteArray(int maxLen) {
        int len = readVarInt();
        if (len < 0 || len > maxLen) {
            throw new SvtDecodeException("array length " + len + " exceeds " + maxLen);
        }
        require(len);
        byte[] value = new byte[len];
        System.arraycopy(data, pos, value, 0, len);
        pos += len;
        return value;
    }

    /**
     * Reads a UUID written as two longs.
     *
     * @return the UUID
     */
    public java.util.UUID readUuid() {
        long most = readLong();
        long least = readLong();
        return new java.util.UUID(most, least);
    }

    /**
     * Reads a long array written by the client custom codec, rejecting
     * a declared count beyond the given maximum.
     *
     * @param maxWords the maximum element count
     * @return the decoded array
     */
    public long[] readLongArray(int maxWords) {
        int count = readVarInt();
        if (count < 0 || count > maxWords) {
            throw new SvtDecodeException("long array count " + count + " exceeds " + maxWords);
        }
        long[] values = new long[count];
        for (int i = 0; i < count; i++) {
            values[i] = readLong();
        }
        return values;
    }
}
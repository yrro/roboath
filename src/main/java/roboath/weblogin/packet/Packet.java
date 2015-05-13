package roboath.weblogin.packet;

import lombok.Builder;
import lombok.Value;

@Value
@Builder
public class Packet {
    // 1. Basic Packet Format

    // The remctl network protocol consists of data packets sent from a client to a server or a server to a client over
    // a TCP connection. The remctl protocol may be used over any port, but the IANA-registered port and the
    // RECOMMENDED default for the protocol is 4373. Each data packet has the following format:

    // 1 octet     flags
    // 4 octets    length
    // <length>    data payload

    // The total size of each token, including the five octet prefix, MUST NOT be larger than 1,048,576 octets (1MB).
    public static final int PAYLOAD_SIZE_LIMIT = (2 << 20) - 5;

    // The flag octet contains one or more of the following values, combined with binary xor:
    public enum Flags {
        TOKEN_NOOP         (1 << 0),
        TOKEN_CONTEXT      (1 << 1),
        TOKEN_DATA         (1 << 2),
        TOKEN_MIC          (1 << 3),
        TOKEN_CONTEXT_NEXT (1 << 4),
        TOKEN_SEND_MIC     (1 << 5),
        TOKEN_PROTOCOL     (1 << 6);

        // Only TOKEN_CONTEXT, TOKEN_CONTEXT_NEXT, TOKEN_DATA, and TOKEN_PROTOCOL are used for packets for versions 2
        // and 3 of the protocol.  The other flags are used only with the legacy version 1 protocol.

        public final int value;

        Flags(int value) {
            this.value = value;
        }
    }

    // (I'm assuming that "xor" is a typo for "or" in the spec --Sam).
    int flags;

    // The length field is a four-octet length in network byte order, specifying the number of octets in the following
    // data payload.

    // The data payload is empty, the results of gss_accept_sec_context, the results of gss_init_sec_context, or a data
    // payload protected with gss_wrap.
    byte[] payload;

    // The length of the data passed to gss_wrap MUST NOT be larger than 65,536 octets (64KB), even if the underlying
    // Kerberos implementation supports longer input buffers.
    public static final int DATA_PAYLOAD_SIZE_LIMIT = (2 << 16);

    public boolean checkFlags(int expected) {
        return expected == flags;
    }

    public String formatFlags() {
        return String.format("0x%02x", flags & 0xff);
    }
}

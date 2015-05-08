package roboath.weblogin;

import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Value;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Optional;

interface Message {
    static final int HIGHEST_VERSION = Arrays.stream(Type.values()).mapToInt(Type::getVersion).max().getAsInt();

    // 2.2. Message Format

    // All client and server messages will use the following format inside the data payload. This is the format of the
    // message before passing it to gss_wrap for confidentiality and integrity protection.

    // 1 octet     protocol version
    // 1 octet     message type
    // <command-specific data>

    static Message parse(byte[] payload) throws UnknownVersion, UnknownMessage, ServerOnly, BadToken {
        ByteBuffer b = ByteBuffer.wrap(payload);

        int version = b.get();
        if (version > Version.HIGHEST_VERSION) {
            throw new UnknownVersion(version);
        }

        int type = b.get();
        return Arrays.stream(Type.values())
            .filter(t -> t.version == version && t.type == type)
            .findFirst()
            .orElseThrow(() -> new UnknownMessage(version, type))
            .parse(b);
    }

    static byte[] encode(Message message) {
        
    }

    class UnknownVersion extends Exception {
        UnknownVersion(int version) {
            super("Received message with version " + version);
        }
    }

    class UnknownMessage extends Exception {
        UnknownMessage(int version, int type) {
            super("Unknown message version:" + version + " type:" + type);
        }
    }

    // The protocol version sent for all messages should be 2 with the exception of MESSAGE_NOOP, which should have a
    // protocol version of 3. The version 1 protocol does not use this message format, and therefore a protocol version
    // of 1 is invalid. See below for protocol version negotiation.

    // The message type is one of the following constants:
    enum Type {
        MESSAGE_COMMAND (1, 2, Command::parseCommand),
        MESSAGE_QUIT    (2, 2, Quit::parseQuit),
        MESSAGE_OUTPUT  (3, 2, null),
        MESSAGE_STATUS  (4, 2, null),
        MESSAGE_ERROR   (5, 2, null),
        MESSAGE_VERSION (6, 2, null),
        MESSAGE_NOOP    (7, 3, Noop::parseNoop);
        // The first two message types are client messages and MUST NOT be sent by the server. The remaining message
        // types except for MESSAGE_NOOP are server messages and MUST NOT by sent by the client.

        // All of these message types were introduced in protocol version 2 except for MESSAGE_NOOP, which is a
        // protocol version 3 message.

        @Getter
        private final int type;

        @Getter
        private final int version;

        @Getter
        @NonNull
        private final Optional<Parser> parser;

        Type(int type, int version, Parser parser) {
            this.type = type;
            this.version = version;
            this.parser = Optional.ofNullable(parser);
        }

        @FunctionalInterface interface Parser {
            Message parse(ByteBuffer b) throws BadToken;
        }

        Message parse(ByteBuffer b) throws ServerOnly, BadToken {
            return parser
                .orElseThrow(() -> new ServerOnly(version, type))
                .parse(b);
        }
    }

    class ServerOnly extends Exception {
        ServerOnly(int version, int type) {
            super("Received server-only message version:" + version + " type:" + type);
        }
    }

    class BadToken extends Exception {
        BadToken(String message) {
            super(message);
        }
    }

    // 2.3. Protocol Version Negotiation

    // If the server ever receives a message from a client that claims a protocol version higher than the server
    // supports, the server MUST otherwise ignore the contents of the message and SHOULD respond with a message type of
    // MESSAGE_VERSION and the following message payload:

    // 1 octet     highest supported version

    // The client MUST then either send only messages supported at that protocol version or lower or send MESSAGE_QUIT
    // and close the connection.

    @Value
    class Version implements Message {
        int getHighestVersion() {
            return (byte)HIGHEST_VERSION;
        }
    }

    // 2.4. MESSAGE_COMMAND

    // Most client messages will be of type MESSAGE_COMMAND, which has the following format:

    @Value
    @Builder
    class Command implements Message {
        // 1 octet     keep-alive flag
        // 1 octet     continue status
        // 4 octets    number of arguments
        // 4 octets    argument length
        //    <length>    argument
        // ...

        // If the keep-alive flag is 0, the server SHOULD close the connection
        // after processing the command. If it is 1, the server SHOULD leave
        // the connection open (up to a timeout period) and wait for more
        // commands. This is similar to HTTP keep-alive.
        boolean keepAlive;

        // If the continue status is 0, it indicates that this is the complete
        // command. If the continue status is 1, it indicates that there is
        // more data coming. The server should accept the data sent, buffer it,
        // and wait for additional messages before running the command or
        // otherwise responding. If the the continue status is 2, it indicates
        // that this message is logically a part of the previous message (which
        // MUST have had a continue status of 1 or 2) and still has more data
        // coming. If the continue status is 3, it says that this message is
        // logically part of the previous message, like 2, but it also says
        // that this is the end of the command.
        enum Continue {
            COMPLETE(0),
            INCOMETE(1),
            CONTINUATION(2),
            FINAL(3);

            public final int value;

            Continue(int value) {
                this.value = value;
            }
        }

        // A continuation of a message starts with the keep-alive flag and
        // continue status and then the next chunk of data. To reconstruct a
        // continued message, remove the first two octets from each chunk and
        // concatenate the pieces together. The result is the portion of a
        // MESSAGE_COMMAND starting with the number of arguments.
        Continue cont;

        // [The stitching-together of multiple MESSAGE_COMMAND messsags is
        // handled within Protocol, so go there for the rest of the remarks
        // on parsing message continuations. --Sam]
        byte[] rest;

        static Command parseCommand(ByteBuffer b) throws BadToken {
            boolean keepAlive = b.get() != 0;
            byte cont = b.get();
            ByteBuffer restBuffer = b.slice();
            byte[] rest = new byte[restBuffer.limit()];
            b.get(rest);
            return builder()
                .keepAlive(keepAlive)
                .cont(
                    Arrays.stream(Continue.values())
                        .filter(c -> c.value == cont)
                        .findFirst()
                        .orElseThrow(() -> new BadToken("Bad continue:" + cont))
                )
                .rest(rest)
                .build();
        }
    }

    // 2.7. MESSAGE_QUIT

    // MESSAGE_QUIT is a way of terminating the connection cleanly if the
    // client asked for keep-alive and then decided not to use it. There is no
    // message body. Upon receiving this message, the server MUST immediately
    // close the connection.
    @Value
    class Quit implements Message {
        static Quit parseQuit(ByteBuffer b) {
            return new Quit();
        }
    }

    // 2.8. MESSAGE_NOOP

    // MESSAGE_NOOP provides a way for a client to keep the connection open to
    // a remctl server, including through firewall session timeouts and similar
    // network constraints that require periodic activity, without sending new
    // commands. There is no body. When the client sends a MESSAGE_NOOP
    // message, the server replies with a MESSAGE_NOOP message.

    @Value
    class Noop implements Message {
        static Noop parseNoop(ByteBuffer b) {
            return new Noop();
        }
    }
}

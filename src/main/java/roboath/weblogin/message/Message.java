package roboath.weblogin.message;

import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Value;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public interface Message {
    int HIGHEST_VERSION = Arrays.stream(Type.values()).map(Type::getHeader).mapToInt(Header::getVersion).max().getAsInt();

    // 2.2. Message Format

    // All client and server messages will use the following format inside the data payload. This is the format of the
    // message before passing it to gss_wrap for confidentiality and integrity protection.

    // 1 octet     protocol version
    // 1 octet     message type
    // <command-specific data>

    static Message parse(byte[] mBytes) throws UnknownVersion, UnknownType, ServerOnly, BadCommand {
        ByteBuffer b = ByteBuffer.wrap(mBytes);

        Header h = Header.parse(b);

        if (h.getVersion() > HIGHEST_VERSION) {
            throw new UnknownVersion(h);
        }

        return Arrays.stream(Message.Type.values())
            .filter(t -> t.getHeader().equals(h))
            .findFirst()
            .orElseThrow(() -> new UnknownType(h))
            .parser.parse(b);
    }

    static Message encode(ByteBuffer b, Message m) {
        m.getHeader().encode(b);
        m.encodeBody(b);
    }

    // The protocol version sent for all messages should be 2 with the exception of MESSAGE_NOOP, which should have a
    // protocol version of 3. The version 1 protocol does not use this message format, and therefore a protocol version
    // of 1 is invalid. See below for protocol version negotiation.

    // The message type is one of the following constants:
    enum Type {
        MESSAGE_COMMAND (Header.builder().type((byte)1).version((byte)2).build(), Command::parse),
        MESSAGE_QUIT    (Header.builder().type((byte)2).version((byte)2).build(), Quit::parse),
        MESSAGE_OUTPUT  (Header.builder().type((byte)3).version((byte)2).build(), Output::parse),
        MESSAGE_STATUS  (Header.builder().type((byte)4).version((byte)2).build(), Status::parse),
        MESSAGE_ERROR   (Header.builder().type((byte)5).version((byte)2).build(), Error::parse),
        MESSAGE_VERSION (Header.builder().type((byte)6).version((byte)2).build(), Version::parse),
        MESSAGE_NOOP    (Header.builder().type((byte)7).version((byte)3).build(), NoOp::parse);
        // The first two message types are client messages and MUST NOT be sent by the server. The remaining message
        // types except for MESSAGE_NOOP are server messages and MUST NOT by sent by the client.

        // All of these message types were introduced in protocol version 2 except for MESSAGE_NOOP, which is a
        // protocol version 3 message.

        @Getter
        @NonNull
        private final Header header;

        @Getter
        @NonNull
        Parser parser;

        Type(Header header, Parser parser) {
            this.header = header;
            this.parser = parser;
        }

        @FunctionalInterface interface Parser {
            Message parse(ByteBuffer b) throws BadCommand, UnknownVersion, UnknownType, ServerOnly;
        }
    }

    Header getHeader();

    void encodeBody(ByteBuffer b);

    class UnknownVersion extends Exception {
        UnknownVersion(Header h) {
            super("Unknown version  (version:" + (h.getVersion() & 0xff) + " type:" + (h.getType() & 0xff));
        }
    }

    class UnknownType extends Exception {
        UnknownType(Header h) {
            super("Unknown type (version: " + (h.getVersion() & 0xff) + " type: " + (h.getType() & 0xff));
        }
    }

    class ServerOnly extends Exception {
        ServerOnly(Header h) {
            super("Received server-only message version:" + (h.getVersion() & 0xff) + " type:" + (h.getType() & 0xff));
        }
    }

    class BadCommand extends Exception {
        BadCommand(String message) {
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
        @Override
        public Header getHeader() {
            return Type.MESSAGE_VERSION.getHeader();
        }

        @Override
        public void encodeBody(ByteBuffer b) {
            b.put((byte)Message.HIGHEST_VERSION);
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
            INCOMPLETE(1),
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

        static Command parse(ByteBuffer b) throws BadCommand {
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
                        .orElseThrow(() -> new BadCommand("Bad continue:" + cont))
                )
                .rest(rest)
                .build();
        }
    }

    class Status implements Message {

        @Override
        public Header getHeader() {
            return null;
        }

        @Override
        public void encodeBody(ByteBuffer b) {

        }
    }

    class Output implements Message {

        @Override
        public Header getHeader() {
            return null;
        }

        @Override
        public void encodeBody(ByteBuffer b) {

        }
    }

    // 2.6. MESSAGE_ERROR

    // At any point before sending MESSAGE_STATUS, the server may respond
    // with MESSAGE_ERROR if some error occurred. This can be the first
    // response after a MESSAGE_COMMAND, or it may be sent after one
    // or more MESSAGE_OUTPUT messages. The format of
    // MESSAGE_ERROR is as follows:

    // 4 octets    error code
    // 4 octets    message length
    // <length>    error message

    enum Error implements Message {
        // The error code is a four-octet number in network byte order
        // indicating the type of error. The error code may be one of the
        // following values:
        ERROR_INTERNAL(1, "Internal server failure"),
        ERROR_BAD_TOKEN(2, "Invalid format in token"),
        ERROR_UNKNOWN_MESSAGE(3, "Unknown message type"),
        ERROR_BAD_COMMAND(4, "Invalid command format in token"),
        ERROR_UNKNOWN_COMMAND(5, "Unknown command"),
        ERROR_ACCESS(6, "Access denied"),
        ERROR_TOOMANY_ARGS(7, "Argument count exceeds server limit"),
        ERROR_TOOMUCH_DATA(8, "Argument size exceeds server limit"),
        ERROR_UNEXPECTED_MESSAGE(9, "Message type not valid now");

       //The message length is a four-octet number in network byte order that
       // specifies the length in octets of the following error message. The
       // error message is a free-form informational message intended for
       // human consumption and MUST NOT be interpreted by an automated
       // process. Software should instead use the error code.

        private final int value;
        private final String message;

        Error (int value, String message) {
            this.value = value;
            this.message = message;
        }

       @Override
        public Header getHeader() {
            return Type.MESSAGE_ERROR.getHeader();
        }

        @Override
        public void encodeBody(ByteBuffer b) {
            b.putInt(value);
            byte[] messageBytes = message.getBytes(StandardCharsets.US_ASCII);
            b.putInt(messageBytes.length);
            b.put(messageBytes);
        }
    }

    // 2.7. MESSAGE_QUIT

    // MESSAGE_QUIT is a way of terminating the connection cleanly if the
    // client asked for keep-alive and then decided not to use it. There is no
    // message body. Upon receiving this message, the server MUST immediately
    // close the connection.
    @Value
    class Quit implements Message {
        static Quit parse(ByteBuffer b) {
            return new Quit();
        }

        @Override
        public Header getHeader() {
            return Type.MESSAGE_QUIT.getHeader();
        }

        @Override
        public void encodeBody(ByteBuffer b) {}
    }

    // 2.8. MESSAGE_NOOP

    // MESSAGE_NOOP provides a way for a client to keep the connection open to
    // a remctl server, including through firewall session timeouts and similar
    // network constraints that require periodic activity, without sending new
    // commands. There is no body. When the client sends a MESSAGE_NOOP
    // message, the server replies with a MESSAGE_NOOP message.

    @Value
    class NoOp implements Message {
        static NoOp parse(ByteBuffer b) {
            return new NoOp();
        }

        @Override
        public Header getHeader() {
            return Type.MESSAGE_NOOP.getHeader();
        }

        @Override
        public void encodeBody(ByteBuffer b) {}
    }
}

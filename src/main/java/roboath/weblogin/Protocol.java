package roboath.weblogin;

import lombok.extern.slf4j.Slf4j;
import org.ietf.jgss.*;
import org.slf4j.MDC;
import roboath.weblogin.message.Message;
import roboath.weblogin.packet.Packet;
import roboath.weblogin.packet.PacketReader;
import roboath.weblogin.packet.PacketWriter;

import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.TimeUnit;

import static roboath.weblogin.packet.Packet.Flags.*;

@Slf4j
class Protocol implements Runnable {
    private static final int READ_TIMEOUT_SECS = 5;

    private final MessageProp inMP = new MessageProp(false);
    private final MessageProp outMP = new MessageProp(true);
    private final roboath.oath.Service oathService;
    private final GSSCredential serverCreds;
    private final Socket socket;

    private boolean running = true;
    private GSSContext ctx;

    public Protocol(roboath.oath.Service oathService, GSSCredential serverCreds, Socket socket) {
        this.oathService = oathService;
        this.serverCreds = serverCreds;
        this.socket = socket;
    }

    @Override
    public void run() {
        MDC.put("client", String.valueOf(socket.getRemoteSocketAddress()));
        log.debug("accepting connection");
        try (
            PacketReader in = new PacketReader(socket.getInputStream());
            PacketWriter out = new PacketWriter(socket.getOutputStream())
        ) {
            // Avoid DOS attacks through clients connecting & never transmitting.
            socket.setSoTimeout((int) TimeUnit.SECONDS.toMillis(READ_TIMEOUT_SECS));
            // XXX doesn't help with write timeouts. Some kind of thread timer dance necessary.

            GSSManager manager = GSSManager.getInstance();
            // input/output streams
            ctx = manager.createContext(serverCreds);
            runConversation(in, out);
        } catch (Exception e) {
            log.warn("Unexpected error", e);
        } finally {
            try {
                ctx.dispose();
            } catch (GSSException e) {
                log.warn("Unable to dispose of GSSContext", e);
            }
            try {
                socket.close();
            } catch (IOException e) {
                log.warn("Unable to close socket", e);
            }
            log.debug("connection closed");
            MDC.remove("client");
        }
    }

    // A remctl connection is always initiated by a client opening a TCP connection to a server. The protocol then
    // proceeds as follows:
    private void runConversation(PacketReader in, PacketWriter out) throws IOException, GSSException {
        readInitialPacket(in);
        if (!running)
            return;

        establishContext(in, out);
        if (!running)
            return;

        MDC.put("gssInitiator", String.valueOf(ctx.getSrcName()));
        MDC.put("gssAcceptor", String.valueOf(ctx.getTargName()));
        try {
            while (running) {
                Message m = null;
                try {
                    m = readMessage(in);
                } catch (Message.UnknownVersion e) {
                    log.info("Client used unknown protocol version", e);
                    writeMessage(out, new Message.Version());
                    continue;
                } catch (Message.BadCommand e) {
                    writeMessage(out, Message.Error.ERROR_BAD_COMMAND);
                    continue;
                } catch (Message.UnknownType |Message.ServerOnly e) {
                    writeMessage(out, Message.Error.ERROR_UNKNOWN_MESSAGE);
                    continue;
                }

                if (m instanceof Message.Quit) {
                    running = false;
                    continue;
                } else if (m instanceof Message.Noop) {
                    writeMessage(out, new Message.Noop());
                    continue;
                } // else ...
            }
        } finally {
            MDC.remove("gssInitiator");
            MDC.remove("gssAcceptor");
        }
    }

    private void readInitialPacket(PacketReader in) throws IOException {
        // Client sends message with an empty payload and flags TOKEN_NOOP, TOKEN_CONTEXT_NEXT, and
        // TOKEN_PROTOCOL (0x51).
        Packet p = in.readPacket();

        // If the client doesn't include TOKEN_PROTOCOL, it is speaking the version 1 protocol, and the server MUST
        // either drop the connection or fall back to the version 1 protocol. This initial message is useless in a pure
        // version 2 or 3 protocol world and is done only for backward compatibility with the version 1 protocol.
        if (p.checkFlags(TOKEN_NOOP.value | TOKEN_CONTEXT_NEXT.value | TOKEN_PROTOCOL.value)) {
            if (p.getPayload().length != 0) {
                log.warn("Client sent initial packet with non-empty length");
                running = false;
            }
            return;
        } else if (p.checkFlags(TOKEN_NOOP.value | TOKEN_CONTEXT_NEXT.value)) {
            log.warn("Client wants to use unimplemented protocol version 1");
            running = false;
            return;
        }

        log.warn("Client sent initial packet with invalid flags {}", p.formatFlags());
        running = false;
    }

    private void establishContext(PacketReader in, PacketWriter out) throws IOException, GSSException {
        do {
            // [Initial pass]
            // Client calls gss_init_sec_context and sends the results as the message body with flags TOKEN_CONTEXT and
            // TOKEN_PROTOCOL (0x42).
            // [Second pass]
            // Client passes data to gss_init_sec_context and replies with the results and TOKEN_CONTEXT and
            // TOKEN_PROTOCOL (0x42).
            Packet ip = in.readPacket();
            if (!ip.checkFlags(TOKEN_CONTEXT.value | TOKEN_PROTOCOL.value)) {
                log.warn("Client sent context-establishment packet with invalid flags {}", ip.formatFlags());
                running = false;
                break;
            }

            // Server replies with the results of gss_accept_sec_context and flags TOKEN_CONTEXT and
            // TOKEN_PROTOCOL (0x42).
            byte[] token = ctx.acceptSecContext(ip.getPayload(), 0, ip.getPayload().length);
            if (token != null) {
                Packet op = Packet.builder()
                    .flags(TOKEN_CONTEXT.value | TOKEN_PROTOCOL.value)
                    .payload(token)
                    .build();

                out.writePacket(op);
            }

            // Server and client repeat, passing in the payload from the last packet from the other side, for as long
            // as GSS-API indicates that continuation is required. If either side drops TOKEN_PROTOCOL from the flags,
            // it is an considered an error and the connect MUST be dropped. (This could be a down-negotiation attack.)
        } while (!ctx.isEstablished());

        // After the establishment of the security context, both client and server MUST confirm that GSS_C_MUTUAL_FLAG,
        // GSS_C_CONF_FLAG, and GSS_C_INTEG_FLAG are set in the resulting security context and MUST immediately close
        // the connection if this is not the case.
        if (!ctx.getMutualAuthState()) {
            log.warn("Mutual authentication is not enabled");
            running = false;
        }
        if (!ctx.getConfState()) {
            log.warn("Confidentiality is not enabled");
            running = false;
        }
        if (!ctx.getIntegState()) {
            log.warn("Integrity is not enabled");
            running = false;
        }

        // It would be preferable to insist on replay and sequence protection (GSS_C_REPLAY_FLAG and
        // GSS_C_SEQUENCE_FLAG) for all contexts, but some older Kerberos GSS-API implementations don't support this
        // and hence it is not mandatory in the protocol. Clients SHOULD always request replay and sequence protection,
        // however, and servers MAY require such protection be negotiated.
        if (!ctx.getReplayDetState()) {
            log.warn("Replay detection is not enabled");
            running = false;
        }
        if (!ctx.getSequenceDetState()) {
            log.warn("Out-of-sequence detection is not enabled");
            running = false;
        }
    }

    private Message readMessage(PacketReader in) throws IOException, GSSException, Message.UnknownVersion, Message.UnknownType, Message.ServerOnly, Message.BadCommand {
        // After the security context has been established, the client and server exchange commands and responses as
        // described below. All commands are sent with flags TOKEN_DATA and TOKEN_PROTOCOL (0x44) and the data payload
        // of all packets is protected with gss_wrap. The conf_req_flag parameter of gss_wrap MUST be set to non-zero,
        // requesting both confidentiality and integrity services.
        Packet p = in.readPacket();

        if (!p.checkFlags(TOKEN_DATA.value | TOKEN_PROTOCOL.value)) {
            log.warn("Client sent data packet with invalid flags {}", p.formatFlags());
            running = false;
            return null;
        }

        byte[] mBytes = ctx.unwrap(p.getPayload(), 0, p.getPayload().length, inMP);
        if (!inMP.getPrivacy()) {
            log.warn("Client sent data without confidentiality protection");
            running = false;
            return null;
        }

        return Message.parse(mBytes);
    }

    private void writeMessage(PacketWriter out, Message message) throws GSSException, IOException {
        byte[] messageBytes = Message.encode(message);

        if (messageBytes.length >= Packet.DATA_PAYLOAD_SIZE_LIMIT)
            throw new IOException("Tried to wrap too much");

        out.writePacket(
            Packet.builder()
                .flags(TOKEN_DATA.value | TOKEN_PROTOCOL.value)
                .payload(ctx.wrap(messageBytes, 0, messageBytes.length, outMP))
                .build()
        );
    }
}

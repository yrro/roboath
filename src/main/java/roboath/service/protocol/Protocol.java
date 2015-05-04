package roboath.service.protocol;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import roboath.service.Service;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.concurrent.TimeUnit;
import java.util.function.BiPredicate;

@Slf4j
public class Protocol implements Runnable {
    private static final int READ_TIMEOUT_SECS = 10;
    private static final int ERROR_COUNT_THRESHOLD = 8;

    private final Service service;
    private final Socket socket;

    private int errorCount = 0;
    private int successCount = 0;
    private int failureCount = 0;

    public Protocol(Service service, Socket socket) {
        this.service = service;
        this.socket = socket;
    }

    @Override
    public void run() {
        MDC.put("client", String.valueOf(socket.getRemoteSocketAddress()));
        log.debug("accepting connection");
        try (
            ProtocolReader in = new ProtocolReader(socket.getInputStream());
            ProtocolWriter out = new ProtocolWriter(socket.getOutputStream())
        ) {
            // Avoid DOS attacks through clients connecting & never transmitting.
            socket.setSoTimeout((int) TimeUnit.SECONDS.toMillis(READ_TIMEOUT_SECS));
            // XXX doesn't help with write timeouts. Some kind of thread timer dance necessary.

            runConversation(in, out);
        } catch (IOException e) {
            log.warn("IO error", e);
        } finally {
            log.debug("connection closed; with successes={}, failures={}, errors={}", successCount, failureCount, errorCount);
            MDC.remove("client");
        }
    }

    private void runConversation(ProtocolReader in, ProtocolWriter out) throws IOException {
        try {
            out.write(Message.GREETING);
            String[] args;
            while ((args = in.readArgs()) != null) {
                try {
                    if (args.length == 0)
                        throw new ProtocolError(Message.SYNTAX_ERROR, "Insufficient arguments");

                    if (dispatch(in, out, args))
                        return;
                } catch (ProtocolError e) {
                    errorCount++;
                    if (errorCount < ERROR_COUNT_THRESHOLD) {
                        out.write(e);
                        continue;
                    } else {
                        out.write(e, true);
                        out.write(new FatalProtocolError(Message.TOO_MANY_ERRORS));
                        return;
                    }
                }
            }
        } catch (FatalProtocolError e) {
            out.write(e);
        }
    }

    private boolean dispatch(ProtocolReader in, ProtocolWriter out, String[] args) throws ProtocolError, IOException {
        switch (args[0]) {
        case "UDATA":
            return udata(in, out, args);

        case "QUIT":
            return quit(in, out, args);

        default:
            throw new ProtocolError(Message.UNKNOWN_COMMAND);
        }
    }

    private boolean quit(ProtocolReader in, ProtocolWriter out, String[] args) throws IOException {
        out.write(Message.GOODBYE);
        return true;
    }

    private boolean udata(ProtocolReader in, ProtocolWriter out, String[] args) throws ProtocolError, IOException {
        if (args.length != 4)
            throw new ProtocolError(Message.SYNTAX_ERROR, "Expected 4 words");
        MDC.put("mode", args[1]);
        MDC.put("user", args[2]);
        try {
            BiPredicate<String, String> validator = validatorFor(args[1]);
            boolean valid = false;
            try {
                valid = validator.test(args[2], args[3]);
            } catch (Exception e) {
                log.error("Error during OTP validation", e);
            }
            if (valid) {
                successCount++;
                out.write(Message.OK);
            } else {
                failureCount++;
                out.write(Message.UNAUTHORIZED);
            }
        } finally {
            MDC.remove("mode");
            MDC.remove("user");
        }
        return false;
    }

    private BiPredicate<String, String> validatorFor(String name) throws ProtocolError {
        switch (name) {
        case "HOTP":
            return service::validateHOTP;
        case "TOTP":
            return service::validateTOTP;
        default:
            throw new ProtocolError(Message.SYNTAX_ERROR, "Mode not recognized");
        }
    }
}


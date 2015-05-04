package roboath.service.protocol;

import lombok.extern.slf4j.Slf4j;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;

@Slf4j
class ProtocolReader implements AutoCloseable {
    private final static int LINE_LENGTH_LIMIT = 256;

    private final byte[] buffer = new byte[LINE_LENGTH_LIMIT];

    private final PushbackInputStream in;

    public ProtocolReader(InputStream in) throws IOException {
        this.in = new PushbackInputStream(new BufferedInputStream(in));
    }

    /**
     * @throws FatalProtocolError Client did something illegal and the connection should be closed, reporting the error to the client.
     * @throws IOException The connection should be closed immediately, without further communication with the client.
     */
    public String[] readArgs() throws FatalProtocolError, IOException {
        for (int i = 0; i < buffer.length; i++) {
            try {
                buffer[i] = (byte) in.read();
            } catch (SocketTimeoutException e) {
                throw new FatalProtocolError(Message.TIMEOUT);
            }

            if (buffer[i] == -1) {
                if (i != 0)
                    log.debug("Premature end of command");
                return null;
            } else if (buffer[i] == '\r') {
                int b = in.read();
                if (b != '\n' && b != -1)
                    in.unread(b);
            }

            if (buffer[i] == '\r' || buffer[i] == '\n') {
                if (i == 0)
                    return new String[0];
                else
                    return new String(buffer, 0, i, StandardCharsets.US_ASCII).split("\\s+");
            }
        }
        throw new FatalProtocolError(Message.SYNTAX_ERROR, "Line too long");
    }

    @Override
    public void close() throws IOException {
        in.close();
    }
}

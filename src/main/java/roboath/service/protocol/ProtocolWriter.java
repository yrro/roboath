package roboath.service.protocol;

import lombok.extern.slf4j.Slf4j;

import java.io.*;
import java.nio.charset.StandardCharsets;

@Slf4j
class ProtocolWriter implements AutoCloseable {
    private final PrintWriter out;

    public ProtocolWriter(OutputStream out) {
        this.out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(out, StandardCharsets.US_ASCII)));
    }

    public void write(Message message) throws IOException {
        log.debug("{} {}", message.getCode(), message.getDescription());

        out.print(message.getCode());
        out.print(' ');
        out.print(message.getDescription());
        out.print("\r\n");
        out.flush();
    }

    public void write(WithProtocolMessage t, boolean partial) throws IOException {
        log.debug("{} {}", t.getProtocolMessage().getCode(), t.getMessage(), t);

        out.print(t.getProtocolMessage().getCode());
        out.print(partial ? '-' : ' ');
        out.print(t.getMessage());
        out.print("\r\n");
        out.flush();
    }

    public void write(WithProtocolMessage t) throws IOException {
        write(t, false);
    }

    public void close() throws IOException {
        out.close();
    }
}

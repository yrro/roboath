package roboath.weblogin.packet;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

public class PacketReader implements AutoCloseable {
    private final DataInputStream in;

    public PacketReader(InputStream in) {
        this.in = new DataInputStream(in);
    }

    public Packet readPacket() throws IOException {
        int flags = in.readByte();

        int payloadSize = in.readInt();
        if (payloadSize < 0 || payloadSize > Packet.PAYLOAD_SIZE_LIMIT)
            throw new IOException("Illegal payload length " + payloadSize);

        byte[] payload = new byte[payloadSize];
        in.readFully(payload);

        return new Packet(flags, payload);
    }

    @Override
    public void close() throws Exception {
        in.close();
    }
}

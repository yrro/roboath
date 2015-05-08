package roboath.weblogin;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;

class PacketWriter implements AutoCloseable {
    private final DataOutputStream out;

    public PacketWriter(OutputStream out) {
        this.out = new DataOutputStream(out);
    }

    public void writePacket(Packet p) throws IOException {
        if (p.getPayload().length < 0 || p.getPayload().length > Packet.PAYLOAD_SIZE_LIMIT)
            throw new IOException("Illegal payload length " + p.getPayload().length);

        out.writeByte(p.getFlags());
        out.writeInt(p.getPayload().length);
        out.write(p.getPayload());
        out.flush();
    }

    @Override
    public void close() throws Exception {
        out.close();
    }
}

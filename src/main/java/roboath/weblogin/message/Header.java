package roboath.weblogin.message;

import lombok.Builder;
import lombok.Value;

import java.nio.ByteBuffer;

@Value
@Builder
public class Header {
    byte version;
    byte type;

    public static Header parse(ByteBuffer b) {
        return builder()
            .version(b.get())
            .type(b.get())
            .build();
    }

    public void encode(ByteBuffer b) {
        b.put(version);
        b.put(type);
    }

}

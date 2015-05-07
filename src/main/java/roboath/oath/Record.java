package roboath.oath;

import lombok.Builder;
import lombok.NonNull;
import lombok.Value;
import lombok.experimental.Wither;

@Value
@Wither
@Builder
public class Record {
    @NonNull String mode;
    @NonNull byte[] key;
    Long movingFactor;
}

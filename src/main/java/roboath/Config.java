package roboath;

import lombok.Builder;
import lombok.NonNull;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;

import java.net.InetSocketAddress;
import java.nio.file.Path;

@Value
@Builder
@Slf4j
public class Config {
    int concurrentClientLimit;
    int shutdownTimeoutSec;
    @NonNull Path privateKey;
    @NonNull Path certificate;
    @NonNull InetSocketAddress bindAddress;

    static class ConfigBuilder {
        ConfigBuilder() {
            concurrentClientLimit(10);
            shutdownTimeoutSec(5);
            bindAddress(new InetSocketAddress(57653));
        }
    }
}

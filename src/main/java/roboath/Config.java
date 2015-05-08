package roboath;

import lombok.Builder;
import lombok.NonNull;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;

import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

@Value
@Builder
@Slf4j
public class Config {
    int concurrentClientLimit;
    int shutdownTimeoutSec;
    @NonNull Path privateKey;
    @NonNull Path certificate;
    @NonNull InetSocketAddress dynaloginBindAddress;
    @NonNull InetSocketAddress webloginBindAddress;
    @NonNull Path loginConfig;
    @NonNull String webloginServicePrincipal; // if not qualified with a realm, realm taken from kerberosRealm
    @NonNull Optional<Path> kerberosConfig; // if not set, uses implementation-specific search
    @NonNull Optional<String> kerberosRealm; // if not set, taken from kerberosConfig
    @NonNull Optional<List<String>> kdcs; // if not set, taken from kerberosConfig
    boolean kerberosDebug;

    static class ConfigBuilder {
        ConfigBuilder() {
            concurrentClientLimit(10);
            shutdownTimeoutSec(5);
            dynaloginBindAddress(new InetSocketAddress(57653));
            webloginBindAddress(new InetSocketAddress(57654));
            kerberosConfig(Optional.empty());
            kerberosRealm(Optional.empty());
            kdcs(Optional.empty());
            kerberosDebug(false);
        }
    }
}

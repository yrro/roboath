package roboath;

import com.google.common.util.concurrent.MoreExecutors;
import com.google.common.util.concurrent.Service;
import com.google.common.util.concurrent.ServiceManager;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.bridge.SLF4JBridgeHandler;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Optional;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Slf4j
public class Roboath {
    public static void main(String[] args) {
        Thread.setDefaultUncaughtExceptionHandler(Roboath::unhandledException);

        // As recommended by SLF4JBridgeHandler documentation
        SLF4JBridgeHandler.removeHandlersForRootLogger();
        SLF4JBridgeHandler.install();

        Config config = Config.builder()
            .privateKey(Paths.get("key-classic.pem"))
            .certificate(Paths.get("cert-classic.pem"))
            .loginConfig(Paths.get("/home/sam/src/roboath/roboath/login.conf"))
            .webloginServicePrincipal("roboath/wintermute.robots.org.uk")
            //.kerberosConfig(Optional.of(Paths.get("krb5.conf")))
            //.kerberosRealm(Optional.of("ROBOTS.ORG.UK"))
            //.kdcs(Optional.of(Arrays.asList("kdc.robots.org.uk")))
            .kerberosDebug(true)
            .build();

        if (config.getKerberosRealm().isPresent() != config.getKdcs().isPresent()) {
            log.error("kerberosRealm and kdcs must both be specified or neither");
            System.exit(1);
        }
        System.setProperty("java.security.auth.login.config", String.valueOf(config.getLoginConfig().toAbsolutePath()));
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
        config.getKerberosConfig().map(Path::toAbsolutePath).map(String::valueOf).ifPresent(path -> System.setProperty("java.security.krb5.conf", path));
        config.getKerberosRealm().ifPresent(realm -> System.setProperty("java.security.krb5.realm", realm));
        config.getKdcs().map(kdcs -> kdcs.stream().collect(Collectors.joining(":"))).ifPresent(kdcs -> System.setProperty("java.security.krb5.kdc", kdcs));
        System.setProperty("sun.security.krb5.debug", String.valueOf(Boolean.valueOf(config.isKerberosDebug())));

        Executor executor = MoreExecutors.getExitingExecutorService(
            (ThreadPoolExecutor) Executors.newFixedThreadPool(config.getConcurrentClientLimit()),
            config.getShutdownTimeoutSec(), TimeUnit.SECONDS
        );

        roboath.oath.Service oathService = new roboath.oath.Service(config);
        roboath.dynalogin.Service dynaloginService = new roboath.dynalogin.Service(config, oathService, executor);
        roboath.weblogin.Service webloginService = new roboath.weblogin.Service(config, oathService, executor);

        ServiceManager sm = new ServiceManager(Arrays.asList(oathService, dynaloginService, webloginService));
        sm.addListener(new ServiceManager.Listener() {
            @Override
            public void failure(Service service) {
                System.exit(1);
            }

            @Override
            public void healthy() {
                log.info("Ready");
                // TODO notify systemd
            }
        });
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            sm.stopAsync().awaitStopped();
        }));
        sm.startAsync();
    }

    private static void unhandledException(Thread t, Throwable e) {
        log.error("Unhandled exception in {}", t, e);
    }
}

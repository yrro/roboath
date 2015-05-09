package roboath;

import com.google.common.util.concurrent.MoreExecutors;
import com.google.common.util.concurrent.Service;
import com.google.common.util.concurrent.ServiceManager;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.bridge.SLF4JBridgeHandler;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

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
            .build();

        Executor executor = MoreExecutors.getExitingExecutorService(
            (ThreadPoolExecutor) Executors.newFixedThreadPool(config.getConcurrentClientLimit()),
            config.getShutdownTimeoutSec(), TimeUnit.SECONDS
        );

        roboath.oath.Service oathService = new roboath.oath.Service(config);
        roboath.dynalogin.Service dynaloginService = new roboath.dynalogin.Service(config, oathService, executor);

        ServiceManager sm = new ServiceManager(Arrays.asList(oathService, dynaloginService));
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

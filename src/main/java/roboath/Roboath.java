package roboath;

import com.google.common.util.concurrent.Service;
import com.google.common.util.concurrent.ServiceManager;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.bridge.SLF4JBridgeHandler;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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

        roboath.oath.Service oathService = new roboath.oath.Service(config);
        roboath.dynalogin.Service dynaloginService = new roboath.dynalogin.Service(config, oathService);

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

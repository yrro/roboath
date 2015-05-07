package roboath.dynalogin;

import com.google.common.util.concurrent.AbstractExecutionThreadService;
import com.google.common.util.concurrent.MoreExecutors;
import lombok.extern.slf4j.Slf4j;
import roboath.Config;
import roboath.tls.ServerSocketFactoryFactory;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import java.io.IOException;
import java.net.SocketException;
import java.util.concurrent.*;

@Slf4j
public class Service extends AbstractExecutionThreadService {
    final static int CONCURRENT_CLIENT_LIMIT = 10;
    final static int SHUTDOWN_TIMEOUT_SECS = 5;

    private final Config config;
    private final roboath.oath.Service oathService;

    private SSLServerSocket serverSocket;
    private ExecutorService executor;

    public Service(Config config, roboath.oath.Service oathService) {
        this.config = config;
        this.oathService = oathService;
    }

    @Override
    protected void startUp() throws Exception {
        ServerSocketFactory ssf = ServerSocketFactoryFactory.getSocketFactory(config.getCertificate(), config.getPrivateKey());
        serverSocket = (SSLServerSocket) ssf.createServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(config.getBindAddress());
        log.info("Listening on {}", serverSocket.getLocalSocketAddress());

        executor = MoreExecutors.getExitingExecutorService(
            (ThreadPoolExecutor) Executors.newFixedThreadPool(CONCURRENT_CLIENT_LIMIT),
            SHUTDOWN_TIMEOUT_SECS, TimeUnit.SECONDS
        );
    }

    @Override
    protected void run() throws Exception {
        for (;;) {
            try {
                executor.execute(new Protocol(oathService, serverSocket.accept()));
            } catch (SocketException e) {
                log.debug("Terminating due to SocketException", e);
                return;
            }
        }
    }

    @Override
    protected void triggerShutdown() {
        try {
            serverSocket.close();
        } catch (IOException e) {
            throw new RuntimeException("Unable to close ServerSocket", e);
        }
    }
}

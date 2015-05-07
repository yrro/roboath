package roboath.service;

import com.google.common.util.concurrent.AbstractExecutionThreadService;
import com.google.common.util.concurrent.MoreExecutors;
import com.lochbridge.oath.otp.HOTPValidationResult;
import com.lochbridge.oath.otp.HOTPValidator;
import com.lochbridge.oath.otp.TOTP;
import lombok.extern.slf4j.Slf4j;
import roboath.Config;
import roboath.protocol.dynalogin.Protocol;
import roboath.service.tls.ServerSocketFactoryFactory;

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

    private SSLServerSocket serverSocket;
    private ConcurrentMap<String, Record> data;
    private ExecutorService executor;

    public Service(Config config) {
        this.config = config;
    }

    @Override
    protected void startUp() throws Exception {
        ServerSocketFactory ssf = ServerSocketFactoryFactory.getSocketFactory(config.getCertificate(), config.getPrivateKey());
        serverSocket = (SSLServerSocket) ssf.createServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(config.getBindAddress());

        data = new ConcurrentHashMap<>();
        data.put("sam", Record.builder().mode("HOTP").key(new byte[20]).movingFactor(200L).build());

        executor = MoreExecutors.getExitingExecutorService(
            (ThreadPoolExecutor) Executors.newFixedThreadPool(CONCURRENT_CLIENT_LIMIT),
            SHUTDOWN_TIMEOUT_SECS, TimeUnit.SECONDS
        );
    }

    @Override
    protected void run() throws Exception {
        log.info("Listening on {}", serverSocket.getLocalSocketAddress());
        for (;;) {
            try {
                executor.execute(new Protocol(this, serverSocket.accept()));
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

    @Override
    protected void shutDown() throws Exception {
        executor.shutdown();
    }

    public boolean validateHOTP(String user, String authcode) {
        Record r = data.get(user);
        if (r == null) {
            log.debug("User not found");
            return false;
        }

        HOTPValidationResult res = HOTPValidator.lookAheadWindow(8)
            .validate(r.getKey(), r.getMovingFactor().intValue(), authcode.length(), authcode);

        data.put(user, r.withMovingFactor(res.getNewMovingFactor()));
        return res.isValid();
    }

    public boolean validateTOTP(String user, String authcode) {
        Record r = data.get(user);
        if (r == null) {
            log.debug("User not found");
            return false;
        }

        TOTP res = TOTP.key(r.getKey())
            .timeStep(TimeUnit.SECONDS.toMillis(30))
            .digits(authcode.length())
            .hmacSha1()
            .build();
        return res.value().equals(authcode);
    }
}

package roboath.dynalogin;

import com.google.common.util.concurrent.AbstractExecutionThreadService;
import lombok.extern.slf4j.Slf4j;
import roboath.Config;
import roboath.tls.SSLContextFactory;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import java.io.IOException;
import java.net.SocketException;
import java.util.concurrent.Executor;

@Slf4j
public class Service extends AbstractExecutionThreadService {
    private final Config config;
    private final roboath.oath.Service oathService;
    private final Executor executor;

    private SSLServerSocket serverSocket;

    public Service(Config config, roboath.oath.Service oathService, Executor executor) {
        this.config = config;
        this.oathService = oathService;
        this.executor = executor;
    }

    @Override
    protected void startUp() throws Exception {
        SSLContext ctx = new SSLContextFactory().getSSLContext(config.getCertificate(), config.getPrivateKey());
        ServerSocketFactory ssf = ctx.getServerSocketFactory();
        serverSocket = (SSLServerSocket) ssf.createServerSocket();
        serverSocket.setReuseAddress(true);

        serverSocket.bind(config.getBindAddress());
        log.info("{} listening on {}", serviceName(), serverSocket.getLocalSocketAddress());
    }

    @Override
    protected void run() throws IOException {
        for (;;) {
            try {
                executor.execute(new Protocol(oathService, serverSocket.accept()));
            } catch (SocketException e) {
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
    protected String serviceName() {
        return "dynalogin";
    }
}

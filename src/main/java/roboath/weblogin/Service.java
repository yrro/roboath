package roboath.weblogin;

import com.google.common.util.concurrent.AbstractExecutionThreadService;
import lombok.extern.slf4j.Slf4j;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import roboath.Config;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.SocketException;
import java.util.concurrent.Executor;

@Slf4j
public class Service extends AbstractExecutionThreadService {
    private static final String KRB5_PRINCIPAL_NAME = "1.2.840.113554.1.2.2.1";
    private static final String KRB5_MECHANISM = "1.2.840.113554.1.2.2";

    private final Config config;
    private final roboath.oath.Service oathService;
    private final Executor executor;

    private ServerSocket serverSocket;
    private GSSCredential serverCreds;

    public Service(Config config, roboath.oath.Service oathService, Executor executor) {
        this.config = config;
        this.oathService = oathService;
        this.executor = executor;
    }

    @Override
    protected void startUp() throws Exception {
        /* get server credentials */
        GSSManager gm = GSSManager.getInstance();
        GSSName serverName = gm.createName(config.getWebloginServicePrincipal(), new Oid(KRB5_PRINCIPAL_NAME));
        serverCreds = gm.createCredential(serverName,
            GSSCredential.INDEFINITE_LIFETIME,
            new Oid(KRB5_MECHANISM),
            GSSCredential.ACCEPT_ONLY
        );

        serverSocket = new ServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(config.getWebloginBindAddress());
        log.info("{} listening on {}", serviceName(), serverSocket.getLocalSocketAddress());
    }

    @Override
    protected void run() throws IOException {
        for (;;) {
            try {
                executor.execute(new Protocol(oathService, serverCreds, serverSocket.accept()));
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
        return "weblogin";
    }
}

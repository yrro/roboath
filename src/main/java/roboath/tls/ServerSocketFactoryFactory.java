package roboath.tls;

import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

public class ServerSocketFactoryFactory {
    public static ServerSocketFactory getSocketFactory(Path certPath, Path keyPath) throws IOException, GeneralSecurityException {
        PrivateKey key;
        try (BufferedReader in = Files.newBufferedReader(keyPath)) {
            KeyReader r = new KeyReader(in);
            key = KeyFactory.getInstance("RSA")
                .generatePrivate(r.readKeySpec());
        }

        Certificate cert;
        try (BufferedInputStream in = new BufferedInputStream(Files.newInputStream(certPath))) {
            cert = CertificateFactory.getInstance("X.509")
                .generateCertificate(in);
        }

        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(null);
        keystore.setCertificateEntry("cert-alias", cert);
        keystore.setKeyEntry("key-alias", key, "changeit".toCharArray(), new Certificate[] {cert});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keystore, "changeit".toCharArray());

        SSLContext c = SSLContext.getInstance("TLSv1.2");
        c.init(kmf.getKeyManagers(), null, new SecureRandom());
        return c.getServerSocketFactory();
    }
}

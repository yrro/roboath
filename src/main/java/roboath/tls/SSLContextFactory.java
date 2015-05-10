package roboath.tls;

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
import java.util.Random;

public class SSLContextFactory {
    private final Random random = new Random();

    public SSLContext getSSLContext(Path certPath, Path keyPath) throws IOException, GeneralSecurityException {
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

        char[] password = new char[128/Character.SIZE];
        for (int i=0; i < password.length; i++)
            password[i] = (char)random.nextInt(Character.MAX_VALUE+1);

        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(null);
        keystore.setCertificateEntry("cert-alias", cert);
        keystore.setKeyEntry("key-alias", key, password, new Certificate[] {cert});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keystore, password);

        SSLContext c = SSLContext.getInstance("TLSv1.2");
        c.init(kmf.getKeyManagers(), null, new SecureRandom());
        return c;
    }
}

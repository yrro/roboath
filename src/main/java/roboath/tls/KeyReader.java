package roboath.tls;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Base64;

@Slf4j
class KeyReader implements AutoCloseable {
    private final Base64.Decoder b64d = Base64.getDecoder();
    private final StringBuilder sb = new StringBuilder();

    private final BufferedReader reader;

    KeyReader(InputStream in) {
        this.reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
    }

    KeySpec readKeySpec() throws IOException {
        boolean inside = false;
        for (String line = reader.readLine(); line != null; line = reader.readLine()) {
            switch (line) {
            case "-----BEGIN RSA PRIVATE KEY-----":
            case "-----BEGIN PRIVATE KEY-----":
                sb.setLength(0);
                inside = true;
                continue;
            case "-----END RSA PRIVATE KEY-----":
                return parsePKCS1(sb.toString());
            case "-----END PRIVATE KEY-----":
                return parsePKCS8(sb.toString());
            default:
                if (inside)
                    sb.append(line);
            }
        }
        if (inside)
            throw new EOFException();
        else
            return null;
    }

    private KeySpec parsePKCS1(String s) throws IOException {
        try (ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(b64d.decode(s)))) {
            RSAPrivateKey k = RSAPrivateKey.getInstance(in.readObject());
            return new RSAPrivateCrtKeySpec(
                k.getModulus(),
                k.getPublicExponent(),
                k.getPrivateExponent(),
                k.getPrime1(),
                k.getPrime2(),
                k.getExponent1(),
                k.getExponent2(),
                k.getCoefficient()
            );
        } catch (Exception e) {
            throw new IOException("Private key not in PKCS#1 format", e);
        }
    }

    private KeySpec parsePKCS8(String s) {
        return new PKCS8EncodedKeySpec(b64d.decode(s));
    }

    @Override
    public void close() throws IOException {
        reader.close();
    }
}

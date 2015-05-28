package roboath.tls

import spock.lang.Specification

import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPrivateKeySpec

class KeyReaderSpec extends Specification {
    KeyReader kr

    KeyReaderSpec(String resource) {
        kr = new KeyReader(this.class.getResourceAsStream(resource))
    }

    def cleanup() {
        kr.close()
    }
}

class PKCS1KeySpec extends KeyReaderSpec {
    PKCS1KeySpec() {
        super('pkcs#1.pem')
    }

    def 'read single key'() {
    when:
        def ks = kr.readKeySpec()
    then:
        ks instanceof RSAPrivateKeySpec
        kr.readKeySpec() == null
    }
}

class PKCS8KeySpec extends KeyReaderSpec {
    PKCS8KeySpec() {
        super('pkcs#8.pem')
    }

    def 'read single key'() {
    when:
        def ks = kr.readKeySpec()
    then:
        ks instanceof PKCS8EncodedKeySpec
        kr.readKeySpec() == null
    }
}

class IncompleteKeySpec extends KeyReaderSpec {
    def IncompleteKeySpec() {
        super('pkcs#8-incomplete')
    }

    def 'read'() {
    when:
        kr.readKeySpec()
    then:
        thrown(EOFException)
    }
}

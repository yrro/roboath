package roboath.tls

import spock.lang.Specification

import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPrivateKeySpec

class KeyReaderSpec extends Specification {
    def kr

    def cleanup() {
        kr.close()
    }

    def 'read pkcs#1 key'() {
    given:
        kr = new KeyReader(this.class.getResourceAsStream('pkcs#1.pem'))
    when:
        def ks = kr.readKeySpec()
    then:
        ks instanceof RSAPrivateKeySpec
        kr.readKeySpec() == null
    }

    def 'read pkcs#8 key'() {
    given:
        kr = new KeyReader(this.class.getResourceAsStream('pkcs#8.pem'))
    when:
        def ks = kr.readKeySpec()
    then:
        ks instanceof PKCS8EncodedKeySpec
        kr.readKeySpec() == null
    }

    def 'incomplete key'() {
    given:
        kr = new KeyReader(this.class.getResourceAsStream('pkcs#8-incomplete.pem'))
    when:
        kr.readKeySpec()
    then:
        thrown(EOFException)
    }
}

package roboath.tls

import spock.lang.Specification

class KeyReaderTest extends Specification {
    def 'PKCS#1 key'() {
    given:
        def r = new KeyReader(new BufferedReader(this.class.getResourceAsStream('pkcs#1.pem')))
    when:
        def ks = r.readKeySpec()
    then:
        ks
        r.readKeySpec() == null
    }

    def 'PKCS#8 key'() {
    given:
        def r = new KeyReader(new BufferedReader(this.class.getResourceAsStream('pkcs#8.pem')))
    when:
        def ks = r.readKeySpec()
    then:
        ks
        r.readKeySpec() == null
    }

    def 'Incomplete key'() {
    given:
        def r = new KeyReader(new BufferedReader(this.class.getResourceAsStream('pkcs#8-incomplete')))
    when:
        r.readKeySpec()
    then:
        EOFException e == thrown()
    }
}

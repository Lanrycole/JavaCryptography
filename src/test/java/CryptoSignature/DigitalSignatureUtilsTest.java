package CryptoSignature;

import CryptoAsymmetric.AsymmetricEncryptionUtils;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

class DigitalSignatureUtilsTest {

    @Test
    void createDigitalSignature() throws Exception {
        KeyPair keyPair = AsymmetricEncryptionUtils.generateRSAKeyPair();
        URL uri = this.getClass().getClassLoader().getResource("demo.txt");
        assert uri != null;
        Path path = Paths.get(uri.toURI());

        byte[] byteArrray = Files.readAllBytes(path);

        byte[] digitalSignature = DigitalSignatureUtils.createDigitalSignature(byteArrray, keyPair.getPrivate());

        assertNotNull(digitalSignature);

        boolean verifyDigitalSignature = DigitalSignatureUtils.verifyDigitalSignature(byteArrray, digitalSignature, keyPair.getPublic());

        assertTrue(verifyDigitalSignature);
    }

    @Test
    void verifyDigitalSignature() {
    }
}
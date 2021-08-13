package KeyStore;

import Cryptosemetric.SymmetricEncryptionUtils;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;

import java.security.KeyStore;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class KeyStoreUtilsTest {

    @Test
    void createPrivateKeyJavaKeyStore() throws Exception{
        SecretKey secretKey = SymmetricEncryptionUtils.createAESKey();
        String secretKeyHex = Arrays.toString(secretKey.getEncoded());
        KeyStore keyStore = KeyStoreUtils.createPrivateKeyJavaKeyStore("password", "foo", secretKey, "keyPassword");
        assertNotNull(keyStore);

        keyStore.load(null, "password".toCharArray());
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection("keyPassword".toCharArray());
        KeyStore.SecretKeyEntry resultEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry("foo", entryPassword);
        SecretKey result = resultEntry.getSecretKey();
        String resultKeyHex = Arrays.toString(result.getEncoded());
        assertEquals(secretKeyHex, resultKeyHex);
    }
}
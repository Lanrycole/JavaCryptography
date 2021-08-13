package Cryptosemetric;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class SymmetricEncryptionUtilsTest {

    String plaintext = "";
    byte[] initializationVector = null;
    SecretKey key = null;

    @Test
    void createAESKey() throws Exception {
        SecretKey secretKey = SymmetricEncryptionUtils.createAESKey();
        System.out.println(Arrays.toString(secretKey.getEncoded()));
        assertNotNull(secretKey);
    }

    @BeforeEach
    public void initEncryption() throws Exception {
        plaintext = "this is just a text";
        initializationVector = SymmetricEncryptionUtils.createInitializationVector();
        key = SymmetricEncryptionUtils.createAESKey();
    }

    @Test
    public void testAESCryptoEncryption() throws Exception {
        byte[] encryptedKey = SymmetricEncryptionUtils.performAESEncryption(plaintext, key, initializationVector);
        assertNotNull(encryptedKey);

    }

    @Test

    public void testAESCryptoDecryption() throws Exception {
        byte[] encryptedKey = SymmetricEncryptionUtils.performAESEncryption(plaintext, key, initializationVector);
        String decryptedKey = SymmetricEncryptionUtils.performAESDecryption(encryptedKey, key, initializationVector);

        System.out.println(decryptedKey);
        assertEquals(plaintext, decryptedKey);

    }


}
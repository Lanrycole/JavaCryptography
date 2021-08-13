package CryptoAsymmetric;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class AsymmetricEncryptionUtilsTest {

    String plainText = "this is the data";
    PrivateKey privateKey = null;
    PublicKey publicKey = null;


    @BeforeEach
    public void initialize() throws  Exception{
        KeyPair keyPair = AsymmetricEncryptionUtils.generateRSAKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey=keyPair.getPublic();
    }

    @Test
    void generateKeyPair() throws NoSuchAlgorithmException {

        KeyPair keyPair = AsymmetricEncryptionUtils.generateRSAKeyPair();
        System.out.println("Private Key: " + Arrays.toString(keyPair.getPrivate().getEncoded()) + " /n");
        System.out.println("Public Key: " + Arrays.toString(keyPair.getPublic().getEncoded()));
        assertNotNull(keyPair);
    }


    @Test
    public  void testAsymmetricEncryption() throws  Exception{
        byte[] encryptedText = AsymmetricEncryptionUtils.performRSAEncryption(plainText, privateKey);

        System.out.println(Arrays.toString(encryptedText));
        assertNotNull(encryptedText);

    }

    @Test
    public  void testAsymmetricDecryption() throws  Exception{
        byte[] encryptedText = AsymmetricEncryptionUtils.performRSAEncryption(plainText, privateKey);
      String result = AsymmetricEncryptionUtils.performRSADecryption(encryptedText, publicKey);
        System.out.println(result);
        assertNotNull(result);
        assertEquals(result, plainText);

    }
}
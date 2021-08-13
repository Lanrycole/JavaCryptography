package Cryptosemetric;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SymmetricEncryptionUtils {

    private static final String AES = "AES";

    private static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";


    public static SecretKey createAESKey() throws Exception {


        //Generates encrypted key
        //Instantiating SecureRandom class
        SecureRandom secureRandom = new SecureRandom();

        //Generating ket of AES typoe
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        //initializing the key
        keyGenerator.init(256, secureRandom);

        //generating final key
        return keyGenerator.generateKey();

    }

    //creating an initialization vector
    public static byte[] createInitializationVector() {
        //creating a vector of bytes
        byte[] initializationVector = new byte[16];
        //Using secure Random to initialize byte
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        //returning a byte of secureRandom
        return initializationVector;
    }

    //AES encryption
    public static byte[] performAESEncryption(String plainText, SecretKey secretKey, byte[] initializationVector) throws Exception {

        //getting instance of AES encryption
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);

        //calling IvParamSpec on the initializationVector input
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        //intiializing cipher to encrypt the plaintext using the secret key and IV paramspec
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        //Finally, return the encrypted text;
        return cipher.doFinal(plainText.getBytes());
    }

    //AES Decryption
    public static String performAESDecryption(byte[] cipherText, SecretKey secretKey, byte[] initializationVector) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] result = cipher.doFinal(cipherText);

        return new String(result);
    }
}

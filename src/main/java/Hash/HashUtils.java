package Hash;

import org.springframework.security.crypto.bcrypt.BCrypt;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class HashUtils {
    private static final String SHA2_ALGORITHM = "SHA-256";


    public static byte[] generateRandomSalt() {
        byte[] salt = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(salt);
        return salt;

    }

    public static byte[] createSHA2Hash(String text, byte[] salt) throws Exception {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        byteArrayOutputStream.write(salt);
        byteArrayOutputStream.write(text.getBytes());

        byte[] hashedValues = byteArrayOutputStream.toByteArray();

        MessageDigest messageDigest = MessageDigest.getInstance(SHA2_ALGORITHM);
        return messageDigest.digest(hashedValues);
    }

    public static String hashedPassword(String password) {

        return BCrypt.hashpw(password, BCrypt.gensalt());
    }

    public static boolean verifyPassword(String pass, String hash) {
        return BCrypt.checkpw(pass, hash);
    }
}

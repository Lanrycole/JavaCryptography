package Hash;

import CryptoAsymmetric.AsymmetricEncryptionUtils;
import com.sun.security.jgss.GSSUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class HashUtilsTest {

    String text = "this will be hashed with a salt";

    byte[] salt = null;

    @BeforeEach
    public void initialize() {
        salt = HashUtils.generateRandomSalt();
    }

    @Test
    void generateRandomSalt() throws Exception {

        System.out.println(Arrays.toString(salt));
        assertNotNull(salt);
    }

    @Test
    void createSHA2Hash() throws Exception {
        byte[] salt = HashUtils.createSHA2Hash(text, this.salt);
        byte[] salt2 = HashUtils.createSHA2Hash(text, this.salt);

        System.out.println(Arrays.toString(salt));
        assertEquals(32, salt.length);
        assertNotNull(salt);
        assertEquals(Arrays.toString(salt), Arrays.toString(salt2));


    }

    @Test
    public void hashPassword(){

        String passs = "Password";

        String hashedPassword = HashUtils.hashedPassword(passs);
        System.out.println(hashedPassword);
        assertNotNull(hashedPassword);

        boolean isPasswordValid = HashUtils.verifyPassword(passs, hashedPassword);

        assertTrue(isPasswordValid);

    }
}
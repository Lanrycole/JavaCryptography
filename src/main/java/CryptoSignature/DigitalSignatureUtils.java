package CryptoSignature;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class DigitalSignatureUtils {

    private static final String SIGNING_ALGORITHM = "SHA256withRSA";


    /**
     *
     * @param input
     * @param privateKey
     * @return a signed signature of the input
     * @throws Exception
     */
    public static byte[] createDigitalSignature(byte[] input, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(SIGNING_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(input);
        return signature.sign();
    }

    /**
     *
     * @param input
     * @param signatureToVerify
     * @param publicKey
     * @return true if signature is verified.
     * @throws Exception
     */
    public static boolean verifyDigitalSignature(byte [] input,
                                                byte[] signatureToVerify,
                                                PublicKey publicKey) throws Exception {

        Signature signature = Signature.getInstance(SIGNING_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(input);
        return signature.verify(signatureToVerify);

    }


}

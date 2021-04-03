import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.*;
import java.nio.charset.StandardCharsets;

public class DigitalSignatureSolution {
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String byteToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
    public static void main(String[] args) throws Exception {
//Read the text file and save to String data
        String fileName = "EncryptionLab/longtext.txt";
        String data = "";
        String line;
        try (BufferedReader bufferedReader = new BufferedReader( new FileReader(fileName))) {
            while((line= bufferedReader.readLine())!=null){
                data = data +"\n" + line;
            }
        } catch(Exception e) {
            System.out.println("error");
        }
        System.out.println("Original content: "+ data);

//TODO: generate a RSA keypair, initialize as 1024 bits, get public key and private key from this keypair.
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyGen.generateKeyPair();
        Key publicKey = keyPair.getPublic();
        Key privateKey = keyPair.getPrivate();

//TODO: Calculate message digest, using MD5 hash function
        MessageDigest msgDigest = MessageDigest.getInstance("MD5");
        msgDigest.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] digest = msgDigest.digest();

//TODO: print the length of output digest byte[], compare the length of file shorttext.txt and longtext.txt
        System.out.println("byte to hex string: " + byteToHex(digest));
        System.out.println("digest array length: " + digest.length);

//TODO: Create RSA("RSA/ECB/PKCS1Padding") cipher object and initialize is as encrypt mode, use PRIVATE key.
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);

//TODO: encrypt digest message
        byte[] signedDigest = rsaCipher.doFinal(digest);

//TODO: print the encrypted message (in base64format String using Base64) 
        String signedDigestHex = byteToHex(signedDigest);
        System.out.println("encrypted msg : " + signedDigestHex);
        System.out.println("encrypted msg length: " + signedDigest.length);
//TODO: Create RSA("RSA/ECB/PKCS1Padding") cipher object and initialize is as decrypt mode, use PUBLIC key.           
        Cipher desCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        desCipher.init(Cipher.DECRYPT_MODE, publicKey);
//TODO: decrypt message
        byte[] decryptedSignedDigest = desCipher.doFinal(signedDigest);
        System.out.println("decryptedSignedDigest length: " + decryptedSignedDigest.length);
//TODO: print the decrypted message (in base64format String using Base64), compare with origin digest 
        String decryptedSignedDigestHex = byteToHex(decryptedSignedDigest);
        System.out.println("decrypted msg: " + decryptedSignedDigestHex);
        System.out.println("decrypted msg length: " + decryptedSignedDigestHex.length());
        System.out.println("compare digest and decrypted digest: " + Arrays.equals(digest, decryptedSignedDigest));


    }

}
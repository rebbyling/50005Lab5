import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import javax.crypto.*;
import java.util.Base64;


public class DesSolution {
    public static void main(String[] args) throws Exception {
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

//TODO: generate secret key using DES algorithm
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        SecretKey desKey = keyGen.generateKey();
//TODO: create cipher object, initialize the ciphers with the given key, choose encryption mode as DES
        Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        desCipher.init(Cipher.ENCRYPT_MODE, desKey);
//TODO: do encryption, by calling method Cipher.doFinal().
        byte[] byteArray = data.getBytes();
        byte[] encryptedByteArray = desCipher.doFinal(byteArray);
        System.out.println(new String(encryptedByteArray));
//TODO: print the length of output encrypted byte[], compare the length of file shorttext.txt and longtext.txt
        System.out.println("length of byte[]: " + encryptedByteArray.length);
//TODO: do format conversion. Turn the encrypted byte[] format into base64format String using Base64
        String base64format = Base64.getEncoder().encodeToString(encryptedByteArray);
//TODO: print the encrypted message (in base64format String format)
        System.out.println("encrypted msg: " + base64format);
//TODO: create cipher object, initialize the ciphers with the given key, choose decryption mode as DES
        desCipher.init(Cipher.DECRYPT_MODE, desKey);
//TODO: do decryption, by calling method Cipher.doFinal().
        byte[] decryptedByteArray = desCipher.doFinal(encryptedByteArray);
//TODO: do format conversion. Convert the decrypted byte[] to String, using "String a = new String(byte_array);"
        String decryptStr = new String(decryptedByteArray);
//TODO: print the decrypted String text and compare it with original text
        System.out.println("decrypted msg: " + decryptStr);
    }
}
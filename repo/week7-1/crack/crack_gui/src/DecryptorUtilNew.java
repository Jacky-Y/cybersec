import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;


public class DecryptorUtilNew {
    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastleProvider());
//        String serializedSystemIniPath = args[0];
//        String ciphertext = args[1];
        String serializedSystemIniPath = "D:\\security\\crack\\SerializedSystemIni.dat";
        String ciphertext = "{AES256}n4hDc0ZjlchRswbFxFl8QeLHdbSZs4MXtG05jxqM8ko=";
        String cleartext = "";
        if (ciphertext.startsWith("{AES256}")) {
            ciphertext = ciphertext.replaceFirst("\\{AES256\\}", "");
            cleartext = decryptAES(serializedSystemIniPath, ciphertext);
        } else if (ciphertext.startsWith("{3DES}")) {
            ciphertext = ciphertext.replaceFirst("\\{3DES\\}", "");
            cleartext = decrypt3DES(serializedSystemIniPath, ciphertext);
        }
        System.out.println(cleartext);
    }

    public static String decrypt(String serializedSystemIniPath, String ciphertext) {
        String cleartext = "";
        try {
            Security.addProvider((Provider)new BouncyCastleProvider());
            if (ciphertext.startsWith("{AES256}")) {
                ciphertext = ciphertext.replaceAll("^[{AES256}]+", "");
                cleartext = decryptAES(serializedSystemIniPath, ciphertext);
            } else if (ciphertext.startsWith("{3DES}")) {
                ciphertext = ciphertext.replaceAll("^[{3DES}]+", "");
                cleartext = decrypt3DES(serializedSystemIniPath, ciphertext);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            cleartext = "exception"+ ex.getMessage();
        }
        return cleartext;
    }

    // the rest of the code...
    public static String decryptAES(String serializedSystemIni, String ciphertext) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        byte[] encryptedPassword1 = Base64.getDecoder().decode(ciphertext);
        // the rest of the code...

        byte[] salt = null;
        byte[] encryptionKey = null;
        String key = "0xccb97558940b82637c8bec3c770f86fa3a391a56";
        char[] password = new char[key.length()];
        key.getChars(0, password.length, password, 0);
        FileInputStream is = new FileInputStream(serializedSystemIni);
        try {
            salt = readBytes(is);
            int version = is.read();
            if (version != -1) {
                encryptionKey = readBytes(is);
                if (version >= 2)
                    encryptionKey = readBytes(is);
            }
        } catch (IOException e) {
            return e.getMessage();
        }
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWITHSHAAND128BITRC2-CBC");
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, 5);
        SecretKey secretKey = keyFactory.generateSecret(pbeKeySpec);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 0);
        Cipher cipher = Cipher.getInstance("PBEWITHSHAAND128BITRC2-CBC");
        cipher.init(2, secretKey, pbeParameterSpec);
        SecretKeySpec secretKeySpec = new SecretKeySpec(cipher.doFinal(encryptionKey), "AES");
        byte[] iv = new byte[16];
        System.arraycopy(encryptedPassword1, 0, iv, 0, 16);
        int encryptedPasswordlength = encryptedPassword1.length - 16;
        byte[] encryptedPassword2 = new byte[encryptedPasswordlength];
        System.arraycopy(encryptedPassword1, 16, encryptedPassword2, 0, encryptedPasswordlength);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher outCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        outCipher.init(2, secretKeySpec, ivParameterSpec);
        byte[] cleartext = outCipher.doFinal(encryptedPassword2);
        return new String(cleartext, "UTF-8");
    }

    public static String decrypt3DES(String serializedSystemIni, String ciphertext) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        byte[] encryptedPassword1 = Base64.getDecoder().decode(ciphertext);
        // the rest of the code...
        byte[] salt = null;
        byte[] encryptionKey = null;
        String PW = "0xccb97558940b82637c8bec3c770f86fa3a391a56";
        char[] password = new char[PW.length()];
        PW.getChars(0, password.length, password, 0);
        FileInputStream is = new FileInputStream(serializedSystemIni);
        try {
            salt = readBytes(is);
            int version = is.read();
            if (version != -1) {
                encryptionKey = readBytes(is);
                if (version >= 2)
                    encryptionKey = readBytes(is);
            }
        } catch (IOException e) {
            return e.getMessage();
        }
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWITHSHAAND128BITRC2-CBC");
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, 5);
        SecretKey secretKey = keyFactory.generateSecret(pbeKeySpec);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 0);
        Cipher cipher = Cipher.getInstance("PBEWITHSHAAND128BITRC2-CBC");
        cipher.init(2, secretKey, pbeParameterSpec);
        SecretKeySpec secretKeySpec = new SecretKeySpec(cipher.doFinal(encryptionKey), "DESEDE");
        byte[] iv = new byte[8];
        System.arraycopy(salt, 0, iv, 0, 4);
        System.arraycopy(salt, 0, iv, 4, 4);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher outCipher = Cipher.getInstance("DESEDE/CBC/PKCS5Padding");
        outCipher.init(2, secretKeySpec, ivParameterSpec);
        byte[] cleartext = outCipher.doFinal(encryptedPassword1);
        return new String(cleartext, "UTF-8");
    }

    public static byte[] readBytes(InputStream stream) throws IOException {
        int length = stream.read();
        byte[] bytes = new byte[length];
        int in = 0;
        while (in < length) {
            int justread = stream.read(bytes, in, length - in);
            if (justread == -1)
                break;
            in += justread;
        }
        if(in < length) {
            throw new IOException("Not enough bytes available in stream");
        }
        return bytes;
    }
}

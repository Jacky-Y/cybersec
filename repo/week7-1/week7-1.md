### 添加一个用户，用户账号密码存储在文件中，把用户密码解密出来

#### 准备内容

- 用户账号密码存储位置为


```
E:\Oracle\Middleware\Oracle_Home\user_projects\domains\base_domain\servers\AdminServer\security\boot.properties
```

- 数据连接账号密码存储在


```
E:\Oracle\Middleware\Oracle_Home\user_projects\domains\base_domain\config\jdbc\JDBC_Data_Source-0-3407-jdbc.xml
E:\Oracle\Middleware\Oracle_Home\user_projects\domains\base_domain\config\jdbc\JDBC_Data_Source-2-3409-jdbc.xml
```

- weblogic加密秘钥位置为


```
E:\Oracle\Middleware\Oracle_Home\user_projects\domains\base_domain\security\SerializedSystemIni.dat
```

- weblogic11之后进行解密时需要用到cryptoj.jar，位置为


```
E:\Oracle\Middleware\Oracle_Home\oracle_common\modules\oracle.rsa\cryptoj.jar
```

- 此外，还需要生成wlfullclient.jar作为基础依赖库


#### 通过java代码进行解密

需要将SerializedSystemIni.dat放在java代码所在目录下，同时导入cryptoj.jar和成wlfullclient.jar，在IDEA中运行

```java
import weblogic.security.internal.*;
import weblogic.security.internal.encryption.*;


import java.io.PrintStream;

public class Decrypt {
    static EncryptionService es = null;
    static ClearOrEncryptedService ces = null;

    public static void main(String[] args) {
        String s = "{AES256}MwonUqMtWF0Lygu08KMRtQz3E2I2Fy5Tt3C2fqRurL0=";

        es = SerializedSystemIni.getExistingEncryptionService();

        if (es == null) {
            System.err.println("Unable to initialize encryption service");
            return;
        }

        ces = new ClearOrEncryptedService(es);

        if (s != null) {
            System.out.println("\nDecrypted Password is:" + ces.decrypt(s));
        }
    }
}
```

在依赖cryptoj.jar和成wlfullclient.jar的情况下，代码可以运行成功，并输出解密结果为weblogic1

![image-20230716165805586](.\images\image-20230716165805586.png)

该代码位于/crack/crack_idea目录下

#### 通过GUI工具进行解密

在网上找到weblogic 解密工具，GitHub地址为[Decrypt_Weblogic_Password/Tools5-weblogic_decrypt at master · TideSec/Decrypt_Weblogic_Password (github.com)](https://github.com/TideSec/Decrypt_Weblogic_Password/tree/master/Tools5-weblogic_decrypt)，但是这个java工具版本太低无法解密，并且没有报错信息，对工具代码进行反编译，发现主要问题在读取的密文格式，该工具只写了处理{AES}开头的密文，而现有较新版本的密文是以{AES256}开头，修改这个逻辑之后，再将代码中较老的库替换为新版，如base64编码等，再将报错信息输出到结果框，然后重新打包为crack_gui.jar，该工具的依赖库bcprov-jdk15on-152.jar需要跟该工具在同一目录下，然后运行crack_gui.jar即可通过图形界面选择密钥文件和输入密文进行解密

反编译后并经过修改的核心代码如下

```java
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


    public static String decryptAES(String serializedSystemIni, String ciphertext) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        byte[] encryptedPassword1 = Base64.getDecoder().decode(ciphertext);

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
```

crack_gui程序可通过图形界面进行解密操作

![image-20230716171637017](.\images\image-20230716171637017.png)

解密工具crack_gui位于/crack目录下，crack_gui的源码位于/crack/crack_gui目录下

#### 通过JSP页面解密

上传JSP页面到weblogic的web应用程序中，访问该jsp页面可以解密

```jsp
<%@page pageEncoding="utf-8"%>
<%@page import="weblogic.security.internal.*,weblogic.security.internal.encryption.*"%>
<%
   EncryptionService es = null;
   ClearOrEncryptedService ces = null;
    String s = null;
    s="{AES}yvGnizbUS0lga6iPA5LkrQdImFiS/DJ8Lw/yeE7Dt0k=";
    es = SerializedSystemIni.getEncryptionService();
    if (es == null) {
       out.println("Unable to initialize encryption service");
        return;
    }
    ces = new ClearOrEncryptedService(es);
    if (s != null) {
        out.println("\nDecrypted Password is:" + ces.decrypt(s));
    }
%>
```



### weblogic rest api 分析

尝试白盒测试，weblogic的服务器逻辑代码主要存储在D:\Oracle\Middleware\Oracle_Home\wlserver\server\lib和D:\Oracle\Middleware\Oracle_Home\wlserver\modules目录下，将这两个目录复制出来，然后用7-zip对目录下所有jar包进行解压，执行以下命令

```
for /R "D:\security\findclass\lib" %i in (*.jar) do "D:\security\7-Zip\7z.exe" x "%i" -o"D:\security\findclass\extract\%~nI" -y

for /R "D:\security\findclass\modules" %i in (*.jar) do "D:\security\7-Zip\7z.exe" x "%i" -o"D:\security\findclass\extract\%~nI" -y
```

然后使用filelocator去对D:\security\findclass\extract目录搜索关键字，尝试定位rest api的处理逻辑

对于rest api：127.0.0.1:7001/management/weblogic/latest/edit/serverTemplateCreateForm，搜索serverTemplateCreateForm，但没有结果

![image-20230716230942127](.\images\image-20230716230942127.png)



搜索latest关键字，几乎所有api都使用latest这个字符表示版本，可以搜到结果，但是结果太多，找其中可能性大的进一步分析

![image-20230716231729994](.\images\image-20230716231729994.png)

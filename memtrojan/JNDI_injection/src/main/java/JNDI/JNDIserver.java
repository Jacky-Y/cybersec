package JNDI;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.naming.Reference;
import java.io.IOException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.Hashtable;

public class JNDIserver {
    public static void main(String[] args) throws NamingException, IOException {

//        Hashtable<String, String> env = new Hashtable<>();
//        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.rmi.registry.RegistryContextFactory");
//        env.put(Context.PROVIDER_URL, "rmi://192.168.0.103:1099");




        Registry registry = LocateRegistry.createRegistry(1099);
        InitialContext initialContext=new InitialContext();

//        initialContext.bind("rmi://192.168.0.103:1099/remoteobj",new HelloImpl());

        Reference refobj=new Reference("TestObj","TestObj","http://localhost:7777/");
        initialContext.bind("rmi://localhost:1099/remoteobj",refobj);

    }
}

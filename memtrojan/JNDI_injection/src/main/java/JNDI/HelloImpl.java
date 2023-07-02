package JNDI;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class HelloImpl implements IHello {
    public HelloImpl() throws RemoteException {
        UnicastRemoteObject.exportObject(this, 0);
    }

    @Override
    public String sayHello(String name) {
        System.out.println(name);
        return name;
    }
}
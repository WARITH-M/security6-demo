package com.alibou.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        // JWT身份验证过滤器（接口过滤器,拦截请求）
        final String authHeader = request.getHeader("Authorization"); // 获取头部授权信息
        final String jwt;
        final String userEmail;
        // 授权信息为空 || 授权信息不是以Bearer 开头，则判断其未授权（Bearer 为jwt字符串开始的几位字符）
        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            // 直接执行下一个过滤器或者业务处理器。不写则无法继续接下来的业务
            filterChain.doFilter(request, response);
            return;
        }
        // 获取令牌，截取除Bearer 之外的字符串
        jwt = authHeader.substring(7);
        // 提取用户名（邮箱）
        userEmail = jwtService.extractUsername(jwt);
        // 邮箱不为空且用户还未经过身份验证
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            // 如果用户令牌有效
            if(jwtService.isTokenValid(jwt, userDetails)){
                // 创建一个用户名、密码、认证令牌，传入用户详情作为认证信息
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                // 传递一个新的web身份验证源，扩展请求细节
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // 更新安全上下文（身份验证令牌）
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        // 执行下一个过滤器或者业务处理器
        filterChain.doFilter(request, response);
    }

}

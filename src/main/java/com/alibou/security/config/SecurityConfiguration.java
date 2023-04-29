package com.alibou.security.config;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {


    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // 安全过滤链
        http
                .csrf() // 禁用csrf
                .disable()
                .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
                            // 允许所有OPTIONS请求
                            .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                            // 允许直接访问授权登录接口
                            .requestMatchers(HttpMethod.POST, "/api/v1/auth/**").permitAll()
                            // 允许 SpringMVC 的默认错误地址匿名访问
                            .requestMatchers("/error").permitAll()
                            // 其他所有接口必须有Authority信息，Authority在登录成功后的UserDetailsImpl对象中默认设置“ROLE_USER”
                            //.requestMatchers("/**").hasAnyAuthority("ROLE_USER")
                            // 允许任意请求被已登录用户访问，不检查Authority
                            .anyRequest().authenticated())
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}

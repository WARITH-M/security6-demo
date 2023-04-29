package com.alibou.security.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity // 实体
@Table(name = "_user") // 表名重命名
public class User implements UserDetails {

    @Id // 指定为ID
    @GeneratedValue // 自动生成值
    private Integer id;
    private String firstname;
    private String lastname;
    private String email;
    private String password;

    @Enumerated(EnumType.STRING) // 枚举类型，一次只有一个角色
    private Role role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 返回用户的角色权限相关
        return List.of(new SimpleGrantedAuthority(role.name())); // 简单授权
    }

    @Override
    public String getPassword() {
        // 获取密码，security中的方法，密码字段名不同时，用于重写密码字段
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

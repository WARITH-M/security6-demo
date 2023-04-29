package com.alibou.security.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {

    // 通过邮箱查找用户
    Optional<User> findByEmail(String email);
}

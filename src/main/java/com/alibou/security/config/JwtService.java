package com.alibou.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    // https://allkeysgenerator.com/     encryption key   选择 yes    SignatureAlgorithm.HS256  加密方法与生成token时一致
    private static final String SECRET_KEY = "7A25432A462D4A614E635266556A586E3272357538782F413F4428472B4B6250";

    /**
     * 获取用户名称
     * @param token
     * @return 用户名称
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * 生成token
     * @param userDetails 用户信息
     * @return token
     */
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * 生成token
     * @param extraClaims 身份信息（这个参数类似一个占位，模型内容由后面的设置来补充）
     * @param userDetails  用户信息
     * @return token
     */
    public String generateToken(Map<String,Object> extraClaims, UserDetails userDetails){
        return Jwts
            .builder()
            .setClaims(extraClaims) // 设置身份信息
            .setSubject(userDetails.getUsername()) // 设置主题，用户名
            .setIssuedAt(new Date(System.currentTimeMillis())) // 令牌生成时间
            .setExpiration(new Date(System.currentTimeMillis() +  1000 * 60 * 24)) // 设置过期时间
            .signWith(getSignInKey(), SignatureAlgorithm.HS256)  // 秘钥与加密算法
            .compact();
    }

    /**
     * 验证token是否过期
     * @param token 令牌
     * @param userDetails 用户信息
     * @return
     */
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    /**
     * 验证token是否过期
     * @param token 令牌
     * @return
     */
    public boolean isTokenExpired(String token){
        // 判断过期时间是否在当前时间之前
        return extractExpiration(token).before(new Date());
    }

    /**
     * 获取过期时间
     * @param token 令牌
     * @return
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * 获取jwt信息中的单个身份信息
     * @param token
     * @param claimsResolver
     * @return jwt信息中的单个信息
     * @param <T>
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * 提取jwt中的身份信息
     * @param token
     * @return Jwts
     */
    private Claims  extractAllClaims(String token){
        return Jwts
            .parserBuilder()
            .setSigningKey(getSignInKey()) // 秘钥
            .build()
            .parseClaimsJws(token)
            .getBody();
    }

    /**
     * 获取签名秘钥
     * @return 签名秘钥
     */
    private Key getSignInKey() {
        // 使用base64来解码这个秘钥
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        // 利用hmacShaKeyFor得到签名秘钥
        return Keys.hmacShaKeyFor(keyBytes);
    }
}

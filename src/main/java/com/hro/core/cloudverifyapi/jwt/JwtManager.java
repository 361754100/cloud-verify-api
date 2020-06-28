package com.hro.core.cloudverifyapi.jwt;

import com.hro.core.cloudverifyapi.enums.ResultCodeEnum;
import com.hro.core.cloudverifyapi.utils.RsaUtil;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Map;

/**
 * Jwt工具类
 */
public class JwtManager {

    private static Logger logger = LoggerFactory.getLogger(JwtManager.class);

    private static RSAPrivateKey priKey;
    private static RSAPublicKey pubKey;

    private static JwtManager instance;

    public static JwtManager getInstance() {
        if(instance == null) {
            instance = HolderClass.manager;
            try {
                Map<String, Object> keyMap = RsaUtil.initKey();
                pubKey = (RSAPublicKey) keyMap.get(RsaUtil.PUBLIC_KEY);
                priKey = (RSAPrivateKey) keyMap.get(RsaUtil.PRIVATE_KEY);
            } catch (Exception e) {
                logger.error("init rsa error...", e);
            }
        }
        return instance;
    }

    private static class HolderClass {
        private static JwtManager manager = new JwtManager();
    }

    /**
     * 获取Token
     * @param uid 用户ID
     * @param exp 失效时间，单位分钟
     * @return
     */
    public static String getToken(String uid, int exp) {
        long endTime = System.currentTimeMillis() + 1000 * exp;
        return Jwts.builder().setSubject(uid).setExpiration(new Date(endTime))
                .signWith(SignatureAlgorithm.RS512, priKey).compact();
    }

    /**
     * 检查Token是否合法
     * @param token
     * @return JWTResult
     */
    public JwtResult checkToken(String token) {
        try {
            Claims claims = Jwts.parser().setSigningKey(pubKey).parseClaimsJws(token).getBody();
            String sub = claims.get("sub", String.class);
            return new JwtResult(true, sub, "合法请求", ResultCodeEnum.SUCCESS.getCode());
        } catch (ExpiredJwtException e) {
            // 在解析JWT字符串时，如果‘过期时间字段’已经早于当前时间，将会抛出ExpiredJwtException异常，说明本次请求已经失效
            return new JwtResult(false, null, "token已过期", ResultCodeEnum.TOKEN_TIMEOUT.getCode());
        } catch (SignatureException e) {
            // 在解析JWT字符串时，如果密钥不正确，将会解析失败，抛出SignatureException异常，说明该JWT字符串是伪造的
            return new JwtResult(false, null, "非法请求", ResultCodeEnum.TOKEN_UNVALIDATE.getCode());
        } catch (Exception e) {
            return new JwtResult(false, null, "非法请求", ResultCodeEnum.TOKEN_UNVALIDATE.getCode());
        }
    }
}

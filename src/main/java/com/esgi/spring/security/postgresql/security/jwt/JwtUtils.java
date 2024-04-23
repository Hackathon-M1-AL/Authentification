package com.esgi.spring.security.postgresql.security.jwt;

import java.security.Key;
import java.util.Date;

import com.esgi.spring.security.postgresql.security.services.UserDetailsImpl;
import com.esgi.spring.security.postgresql.utils.exception.CustomMalformedJwtException;
import com.esgi.spring.security.postgresql.utils.exception.CustomExpiredJwtTokenException;
import com.esgi.spring.security.postgresql.utils.exception.CustomTechnicalJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${esgi.app.jwtSecret}")
    private String jwtSecret;

    @Value("${esgi.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String generateJwtToken(UserDetailsImpl userPrincipal) {
        return generateTokenFromUsername(userPrincipal.getUsername());
    }

    public String generateTokenFromUsername(String username) {
        return Jwts.builder()
                   .setSubject(username)
                   .setIssuedAt(new Date())
                   .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                   .signWith(key(), SignatureAlgorithm.HS256)
                   .compact();
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parserBuilder()
                   .setSigningKey(key())
                   .build()
                   .parseClaimsJws(token)
                   .getBody()
                   .getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parserBuilder()
                .setSigningKey(key())
                .build()
                .parse(authToken);
            return true;
        } catch (MalformedJwtException exception) {
            logger.error("Invalid JWT token: {}", exception.getMessage());
            throw new CustomMalformedJwtException();
        } catch (ExpiredJwtException exception) {
            logger.error("JWT token is expired: {}", exception.getMessage());
            throw new CustomExpiredJwtTokenException();
        } catch (UnsupportedJwtException exception) {
            logger.error("JWT token is unsupported: {}", exception.getMessage());
            throw new CustomTechnicalJwtException();
        } catch (IllegalArgumentException exception) {
            logger.error("JWT claims string is empty: {}", exception.getMessage());
            throw new CustomTechnicalJwtException();
        } catch (SignatureException exception) {
            logger.error("JWT signature does not match: {}", exception.getMessage());
            throw new CustomTechnicalJwtException();
        }
    }
}
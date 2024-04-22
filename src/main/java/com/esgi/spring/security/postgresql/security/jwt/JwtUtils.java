package com.esgi.spring.security.postgresql.security.jwt;

import java.security.Key;
import java.util.Date;
import java.util.List;

import com.esgi.spring.security.postgresql.security.services.UserDetailsImpl;
import com.esgi.spring.security.postgresql.utils.exception.CustomMalformedJwtException;
import com.esgi.spring.security.postgresql.utils.exception.ExpiredJwtTokenException;
import com.esgi.spring.security.postgresql.utils.exception.TechnicalJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
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

    public String generateJwtToken(Authentication authentication) {

        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        List<String> roles = userPrincipal.getAuthorities()
                                          .stream()
                                          .map(GrantedAuthority::getAuthority)
                                          .toList();

        return Jwts.builder()
                   .setSubject((userPrincipal.getUsername()))
                   .setIssuedAt(new Date())
                   .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                   .signWith(key(), SignatureAlgorithm.HS256)
                   .claim("roles", roles)
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
            throw new ExpiredJwtTokenException();
        } catch (UnsupportedJwtException exception) {
            logger.error("JWT token is unsupported: {}", exception.getMessage());
            throw new TechnicalJwtException();
        } catch (IllegalArgumentException exception) {
            logger.error("JWT claims string is empty: {}", exception.getMessage());
            throw new TechnicalJwtException();
        }
    }
}

package com.esgi.spring.security.postgresql.security.services;

import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
public class TokenBlacklist {
    private Set<String> blacklistedTokens = new HashSet<>();

    public boolean isBlacklisted(String token) {
        return blacklistedTokens.contains(token);
    }

    public void blacklistToken(String token) {
        blacklistedTokens.add(token);
    }
}


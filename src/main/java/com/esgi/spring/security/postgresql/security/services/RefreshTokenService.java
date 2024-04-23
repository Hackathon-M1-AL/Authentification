package com.esgi.spring.security.postgresql.security.services;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import com.esgi.spring.security.postgresql.models.RefreshToken;
import com.esgi.spring.security.postgresql.models.User;
import com.esgi.spring.security.postgresql.repository.RefreshTokenRepository;
import com.esgi.spring.security.postgresql.repository.UserRepository;
import com.esgi.spring.security.postgresql.utils.exception.TokenRefreshException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RefreshTokenService {
    @Value("${esgi.app.jwtRefreshExpirationMs}")
    private Long refreshTokenDurationMs;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken createRefreshToken(Long userId) {
        Optional<User> optionalUser = userRepository.findById(userId);
        if (optionalUser.isEmpty()) {
            throw new IllegalArgumentException("User not found with ID: " + userId);
        }

        Optional<RefreshToken> existingToken = refreshTokenRepository.findByUser(optionalUser.get());
        if (existingToken.isPresent()) {
            // If a refresh token already exists for the user, update or delete it
            RefreshToken token = existingToken.get();
            token.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
            token.setToken(UUID.randomUUID().toString());
            return refreshTokenRepository.save(token);
        } else {
            // If no refresh token exists, create a new one
            RefreshToken refreshToken = new RefreshToken();
            refreshToken.setUser(optionalUser.get());
            refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
            refreshToken.setToken(UUID.randomUUID().toString());
            return refreshTokenRepository.save(refreshToken);
        }
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token was expired. Please make a new signin request");
        }

        return token;
    }

    @Transactional
    public int deleteByUserId(Long userId) {
        return refreshTokenRepository.deleteByUser(userRepository.findById(userId).get());
    }
}
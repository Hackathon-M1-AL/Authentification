package com.esgi.spring.security.postgresql.repository;

import com.esgi.spring.security.postgresql.models.RefreshToken;
import com.esgi.spring.security.postgresql.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    Optional<RefreshToken> findByUser(User user);

    @Query(
            value = "SELECT u FROM RefreshToken rt JOIN User u ON u.id = rt.user.id " +
                    "WHERE rt.token = :token"
            )
    Optional<User> findUserByToken(String token);

    @Modifying
    int deleteByUser(User user);
}
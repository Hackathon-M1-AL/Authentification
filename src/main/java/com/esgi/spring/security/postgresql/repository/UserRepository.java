package com.esgi.spring.security.postgresql.repository;

import java.util.Optional;

import com.esgi.spring.security.postgresql.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.esgi.spring.security.postgresql.models.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
  Optional<User> findByUsername(String username);

  Boolean existsByUsername(String username);

  Boolean existsByEmail(String email);

//  @Query(value = "SELECT r FROM User u JOIN Role r ON u.id = r.id WHERE u.username =?1")
//  Optional<Set<Role>> findRolesByUserName(String userName)
}

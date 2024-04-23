/*package com.esgi.spring.security.postgresql.config;

import com.esgi.spring.security.postgresql.models.ERole;
import com.esgi.spring.security.postgresql.models.Role;
import com.esgi.spring.security.postgresql.repository.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.annotation.Transactional;

@Configuration
public class RoleInitializer {

    @Bean
    CommandLineRunner initRoles(RoleRepository roleRepository) {
        return args -> {
            createRoleIfNotFound(roleRepository, ERole.ROLE_USER);
            createRoleIfNotFound(roleRepository, ERole.ROLE_MODERATOR);
            createRoleIfNotFound(roleRepository, ERole.ROLE_ADMIN);
        };
    }

    @Transactional
    void createRoleIfNotFound(RoleRepository roleRepository, ERole name) {
        if (roleRepository.findByName(name).isEmpty()) {
            Role role = new Role();
            role.setName(name);
            roleRepository.save(role);
        }
    }
}
*/
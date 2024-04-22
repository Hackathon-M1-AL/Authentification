package com.esgi.spring.security.postgresql.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import com.esgi.spring.security.postgresql.models.ERole;
import com.esgi.spring.security.postgresql.payload.request.LoginRequest;
import com.esgi.spring.security.postgresql.security.jwt.JwtUtils;
import com.esgi.spring.security.postgresql.security.services.UserDetailsImpl;
import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.esgi.spring.security.postgresql.models.Role;
import com.esgi.spring.security.postgresql.models.User;
import com.esgi.spring.security.postgresql.payload.request.SignupRequest;
import com.esgi.spring.security.postgresql.payload.response.JwtResponse;
import com.esgi.spring.security.postgresql.payload.response.MessageResponse;
import com.esgi.spring.security.postgresql.repository.RoleRepository;
import com.esgi.spring.security.postgresql.repository.UserRepository;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(
            @Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),
                                                                      loginRequest.getPassword()));

        SecurityContextHolder.getContext()
                             .setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities()
                                        .stream()
                                        .map(item -> item.getAuthority())
                                        .collect(Collectors.toList());

        return ResponseEntity
                .ok(new JwtResponse(jwt,
                                    userDetails.getId(),
                                    userDetails.getUsername(),
                                    userDetails.getEmail(),
                                    roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(
            @Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest()
                                 .body(new MessageResponse(
                                         "Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest()
                                 .body(new MessageResponse(
                                         "Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(), signUpRequest.getEmail(),
                             encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role>   roles    = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                          .orElseThrow(() -> new RuntimeException(
                                                  "Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                                       .orElseThrow(() -> new RuntimeException(
                                                               "Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                                     .orElseThrow(() -> new RuntimeException(
                                                             "Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                                      .orElseThrow(() -> new RuntimeException(
                                                              "Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/verifyToken")
    public ResponseEntity<?> verifyToken(@RequestHeader("Authorization")
                                         String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest()
                                 .body(new MessageResponse(
                                               "Error: Authorization header is missing or does not contain Bearer token."
                                       )
                                 );
        }

        String token = authHeader.substring(7); // Remove "Bearer " prefix

        if (!jwtUtils.validateJwtToken(token)) {
            return ResponseEntity.badRequest()
                                 .body(new MessageResponse("Error: Invalid JWT Token."));
        }

        String username = jwtUtils.getUserNameFromJwtToken(token);
        UserDetailsImpl userDetails = (UserDetailsImpl) userRepository.findByUsername(
                                                                              username)
                                                                      .orElseThrow(() -> new RuntimeException(
                                                                              "Error: User not found."))
                                                                      .getRoles();

        List<String> roles = userDetails.getAuthorities()
                                        .stream()
                                        .map(item -> item.getAuthority())
                                        .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(token,
                                                 userDetails.getId(),
                                                 userDetails.getUsername(),
                                                 userDetails.getEmail(),
                                                 roles));
    }
}

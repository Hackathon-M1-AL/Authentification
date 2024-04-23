package com.esgi.spring.security.postgresql.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import com.esgi.spring.security.postgresql.models.ERole;
import com.esgi.spring.security.postgresql.models.RefreshToken;
import com.esgi.spring.security.postgresql.payload.request.ChangePasswordRequest;
import com.esgi.spring.security.postgresql.payload.request.LoginRequest;
import com.esgi.spring.security.postgresql.payload.request.TokenRefreshRequest;
import com.esgi.spring.security.postgresql.payload.response.TokenRefreshResponse;
import com.esgi.spring.security.postgresql.security.jwt.JwtUtils;
import com.esgi.spring.security.postgresql.security.services.RefreshTokenService;
import com.esgi.spring.security.postgresql.security.services.UserDetailsImpl;
import com.esgi.spring.security.postgresql.utils.exception.CustomMalformedJwtException;
import com.esgi.spring.security.postgresql.utils.exception.CustomExpiredJwtTokenException;
import com.esgi.spring.security.postgresql.utils.exception.TokenRefreshException;
import jakarta.validation.Valid;

import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
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

    Logger logger = org.slf4j.LoggerFactory.getLogger(AuthController.class);

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

    @Autowired
    RefreshTokenService refreshTokenService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(
            @Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),
                                                                      loginRequest.getPassword()));

        SecurityContextHolder.getContext()
                             .setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        String jwt = jwtUtils.generateJwtToken(authentication);

        List<String> roles = userDetails.getAuthorities()
                                        .stream()
                                        .map(item -> item.getAuthority())
                                        .toList();

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

        return ResponseEntity.ok(new JwtResponse(jwt,
                                                 refreshToken.getToken(),
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
                    case "ROLE_ADMIN":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                                       .orElseThrow(() -> new RuntimeException(
                                                               "Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "ROLE_MODERATOR":
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

    @GetMapping("/verifytoken")
    public ResponseEntity<?> verifyToken(@RequestHeader("Authorization") String tokenHeader) {
        boolean isValid = validateToken(tokenHeader);

        if (isValid) {
            return ResponseEntity.ok(new MessageResponse("Token is valid"));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("Token is invalid or expired"));
        }
    }

    // Extract and validate JWT token from the Authorization header
    private boolean validateToken(String header) {
        if (header != null && header.startsWith("Bearer ")) {
            String jwtToken = header.substring(7); // Remove "Bearer " prefix
            try {
                return jwtUtils.validateJwtToken(jwtToken);
            } catch (Exception e) {
                // Handle any exceptions if needed
                return false;
            }
        }
        return false;
    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenRefreshRequest request,
                                          @RequestHeader("Authorization")
                                          String authorizationHeader) {
        String requestRefreshToken = authorizationHeader.split(" ")[1];

        return refreshTokenService.findByToken(requestRefreshToken)
                                  .map(refreshTokenService::verifyExpiration)
                                  .map(RefreshToken::getUser)
                                  .map(user -> {
                                      String jwt = jwtUtils.generateJwtTokenFromUsernameAndOldTokenRoles(
                                              user.getUsername());
                                      return ResponseEntity.ok(new TokenRefreshResponse(
                                              jwt,
                                              requestRefreshToken));
                                  })
                                  .orElseThrow(() -> new TokenRefreshException());

//        refreshTokenService.findByToken(requestRefreshToken);
//
//        String requestRefreshToken = request.getRefreshToken();
//
//        Authentication authentication = authenticationManager
//                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
//
//        return refreshTokenService.findByToken(requestRefreshToken)
//                .map(refreshTokenService::verifyExpiration)
//                .map(RefreshToken::getUser)
//                .map(user -> {
//                    String token =
//                            jwtUtils.generateRefreshTokenFromUsername(user.getUsername());
//                    return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
//                })
//                .orElseThrow(() -> new TokenRefreshException());
    }

    @PostMapping("/changepassword")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    // Restrict access to authenticated users with USER or ADMIN role
    public ResponseEntity<?> changePassword(
            @Valid @RequestBody ChangePasswordRequest changePasswordRequest) {
        UserDetailsImpl userDetails = (UserDetailsImpl) SecurityContextHolder.getContext()
                                                                             .getAuthentication()
                                                                             .getPrincipal();
        User user = userRepository.findById(userDetails.getId())
                                  .orElseThrow(() -> new RuntimeException(
                                          "Error: User not found."));

        if (!encoder.matches(changePasswordRequest.getOldPassword(),
                             user.getPassword())) {
            return ResponseEntity.badRequest()
                                 .body(new MessageResponse(
                                         "Error: Old password is incorrect."));
        }

        user.setPassword(encoder.encode(changePasswordRequest.getNewPassword()));
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("Password changed successfully!"));
    }

    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser() {
        UserDetailsImpl userDetails = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Long userId = userDetails.getId();
        refreshTokenService.deleteByUserId(userId);
        return ResponseEntity.ok(new MessageResponse("Log out successful!"));
    }
}

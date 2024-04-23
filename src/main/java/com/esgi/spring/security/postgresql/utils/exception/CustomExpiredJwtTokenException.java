package com.esgi.spring.security.postgresql.utils.exception;

import org.springframework.http.HttpStatus;

public class CustomExpiredJwtTokenException extends SecurityException {


    public CustomExpiredJwtTokenException() {
        super("/refresh", "JWT token is expired", HttpStatus.UNAUTHORIZED);
    }
}

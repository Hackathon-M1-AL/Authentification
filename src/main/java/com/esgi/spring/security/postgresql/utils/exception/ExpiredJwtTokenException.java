package com.esgi.spring.security.postgresql.utils.exception;

import org.springframework.http.HttpStatus;

public class ExpiredJwtTokenException extends SecurityException {


    public ExpiredJwtTokenException() {
        super("/refresh", "JWT token is expired", HttpStatus.UNAUTHORIZED);
    }
}

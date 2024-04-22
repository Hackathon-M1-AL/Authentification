package com.esgi.spring.security.postgresql.utils.exception;

import org.springframework.http.HttpStatus;

public class ExpiredJwtToken extends SecurityException{

    public ExpiredJwtToken(String message) {
        super(message, HttpStatus.UNAUTHORIZED);
    }
}

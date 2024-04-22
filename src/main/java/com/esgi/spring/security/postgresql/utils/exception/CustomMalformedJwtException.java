package com.esgi.spring.security.postgresql.utils.exception;

import org.springframework.http.HttpStatus;

public class CustomMalformedJwtException extends TechnicalJwtException {
    public CustomMalformedJwtException() {
        super("Token mal formatté");
    }
}

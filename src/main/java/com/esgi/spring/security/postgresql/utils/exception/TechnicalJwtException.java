package com.esgi.spring.security.postgresql.utils.exception;

import org.springframework.http.HttpStatus;

public class TechnicalJwtException extends SecurityException {
    public TechnicalJwtException() {
        super("/error", "Erreur technique lié au token", HttpStatus.BAD_REQUEST);
    }

    public TechnicalJwtException(String message) {
        super("/error", message, HttpStatus.BAD_REQUEST);
    }
}

package com.esgi.spring.security.postgresql.utils.exception;

import org.springframework.http.HttpStatus;

public class CustomTechnicalJwtException extends SecurityException {
    public CustomTechnicalJwtException() {
        super("/error", "Erreur technique lié au token", HttpStatus.BAD_REQUEST);
    }

    public CustomTechnicalJwtException(String message) {
        super("/error", message, HttpStatus.BAD_REQUEST);
    }
}

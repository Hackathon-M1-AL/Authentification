package com.esgi.spring.security.postgresql.utils.exception;

public class CustomMalformedJwtException extends CustomTechnicalJwtException {
    public CustomMalformedJwtException() {
        super("Token mal formatté");
    }
}

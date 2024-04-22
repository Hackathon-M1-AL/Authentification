package com.esgi.spring.security.postgresql.utils.exception;

import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpStatus;

public class SecurityException extends JwtException {

    protected String path;
    protected final int httpStatus;

    public SecurityException(String path, String message, final HttpStatus httpStatus) {
        super(message);
        this.path = path;
        this.httpStatus = httpStatus.value();
    }

    public int getHttpStatus() {
        return httpStatus;
    }
}

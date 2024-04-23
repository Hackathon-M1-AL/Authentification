package com.esgi.spring.security.postgresql.utils.exception;

import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpStatus;

public class SecurityException extends JwtException {

    protected       String message;
    protected       String path;
    protected final int    httpStatus;

    public SecurityException(String path, String message,
                             final HttpStatus httpStatus) {
        super(message);
        this.message    = message;
        this.path       = path;
        this.httpStatus = httpStatus.value();
    }

    public int getHttpStatus() {
        return httpStatus;
    }

    public String getPath() {
        return path;
    }

    public String getMessage() {
        return message;
    }
}

package com.esgi.spring.security.postgresql.utils.exception;

import org.springframework.http.HttpStatus;

public class SecurityException extends Exception{

    protected final int httpStatus;

    public SecurityException(String message, final HttpStatus httpStatus) {
        super(message);
        this.httpStatus = httpStatus.value();
    }

    public int getHttpStatus() {
        return httpStatus;
    }
}

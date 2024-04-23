package com.esgi.spring.security.postgresql.utils.exception;


import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.FORBIDDEN)
public class TokenRefreshException extends SecurityException {

    public TokenRefreshException() {
        super("/error", "Refresh token is not in database!", HttpStatus.BAD_REQUEST);
    }
}

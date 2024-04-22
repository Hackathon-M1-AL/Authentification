package com.esgi.spring.security.postgresql.controllers;

import com.esgi.spring.security.postgresql.payload.response.MessageResponse;
import com.esgi.spring.security.postgresql.utils.exception.ExpiredJwtToken;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

@ControllerAdvice
public class ControllorAdvice {

    @ExceptionHandler(ExpiredJwtToken.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ResponseEntity<?> handleException(Exception e) {
        return ResponseEntity.badRequest()
                             .body(new MessageResponse(e.getMessage()));
    }
}

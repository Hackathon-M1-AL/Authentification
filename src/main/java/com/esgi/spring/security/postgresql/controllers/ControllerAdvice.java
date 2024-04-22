package com.esgi.spring.security.postgresql.controllers;

import com.esgi.spring.security.postgresql.payload.response.MessageResponse;
import com.esgi.spring.security.postgresql.utils.exception.ExpiredJwtTokenException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

@org.springframework.web.bind.annotation.ControllerAdvice
public class ControllerAdvice {

   /* @ExceptionHandler(ExpiredJwtTokenException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ResponseEntity<?> handleException(Exception e) {
        return ResponseEntity.badRequest()
                             .body(new MessageResponse(e.getMessage()));
    }*/
}

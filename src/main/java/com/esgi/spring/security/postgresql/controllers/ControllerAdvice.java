package com.esgi.spring.security.postgresql.controllers;

import com.esgi.spring.security.postgresql.payload.response.JwtErrorDTO;
import com.esgi.spring.security.postgresql.payload.response.MessageResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

@org.springframework.web.bind.annotation.ControllerAdvice
public class ControllerAdvice {

//    private static final ObjectMapper mapper = new ObjectMapper();
//
//    @ExceptionHandler(Exception.class)
//    @ResponseStatus(HttpStatus.BAD_REQUEST)
//    public ResponseEntity<?> handleException(Exception e) {
//        JwtErrorDTO jwtResponse = new JwtErrorDTO("/error",
//                                                  HttpStatus.BAD_REQUEST.getReasonPhrase(),
//                                                  e.getMessage(),
//                                                  HttpStatus.BAD_REQUEST.value());
//
//
//        return ResponseEntity.badRequest()
//                             .body(mapper.convertValue(jwtResponse,
//                                                       JwtErrorDTO.class));
//    }
}

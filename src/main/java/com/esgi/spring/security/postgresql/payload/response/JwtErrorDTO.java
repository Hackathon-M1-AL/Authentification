package com.esgi.spring.security.postgresql.payload.response;

import org.springframework.http.HttpStatus;


public class JwtErrorDTO {
    private String path;
    private String message;
    private int status;

    public JwtErrorDTO(String path, String error, String message, int status){
        this.path = path;
        this.message = message;
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public String getPath() {
        return path;
    }

    public int getStatus() {
        return status;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public void setStatus(int status) {
        this.status = status;
    }
}
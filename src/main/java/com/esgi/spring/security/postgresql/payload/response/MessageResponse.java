package com.esgi.spring.security.postgresql.payload.response;

public class MessageResponse {
  private String message;

  public MessageResponse(String message) {
    this.message = message;
  }

  public MessageResponse(Exception exception) {
    this.message = exception.getMessage();
  }

  public String getMessage() {
    return message;
  }

  public void setMessage(String message) {
    this.message = message;
  }
}

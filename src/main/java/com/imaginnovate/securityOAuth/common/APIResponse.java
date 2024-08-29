package com.imaginnovate.securityOAuth.common;

import lombok.Data;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@Data
public class APIResponse {
    private boolean success;
    private String message;
    private Object data;



    public static ResponseEntity<APIResponse> success(Object data) {
        APIResponse response = new APIResponse();
        response.setSuccess(true);
        response.setData(data);
        return ResponseEntity.ok(response);
    }

    public static ResponseEntity<APIResponse> success(String message, Object data) {
        APIResponse response = new APIResponse();
        response.setSuccess(true);
        response.setData(data);
        response.setMessage(message);
        return ResponseEntity.ok(response);
    }

    public static ResponseEntity<APIResponse> error(String message) {
        APIResponse response = new APIResponse();
        response.setSuccess(false);
        response.setMessage(message);
        response.setData(null);
        return ResponseEntity.badRequest().body(response);
    }

    public static ResponseEntity<APIResponse> error(String message,Object data) {
        APIResponse response = new APIResponse();
        response.setSuccess(false);
        response.setMessage(message);
        response.setData(data);
        return ResponseEntity.badRequest().body(response);
    }

    public static ResponseEntity<APIResponse> error(HttpStatus status, String message) {
        APIResponse response = new APIResponse();
        response.setSuccess(false);
        response.setMessage(message);
        response.setData(null);
        return ResponseEntity.status(status).body(response);
    }


    public void setSuccess(boolean success) {
        this.success = success;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public void setData(Object data) {
        this.data = data;
    }

    public boolean isSuccess() {
        return success;
    }

    public String getMessage() {
        return message;
    }

    public Object getData() {
        return data;
    }
}
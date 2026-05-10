package com.tcc.security.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class DataAccessDeniedHandler {

    @ExceptionHandler(DataAccessDeniedException.class)
    public ResponseEntity<Map<String, String>> handleDataAccessDenied(DataAccessDeniedException ex, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "access_denied", "reason", ex.getMessage()));
    }
}

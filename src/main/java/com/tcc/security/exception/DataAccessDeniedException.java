package com.tcc.security.exception;

public class DataAccessDeniedException extends RuntimeException {
    public DataAccessDeniedException(String message) {
        super(message);
    }
}

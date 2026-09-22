package com.github.h3yow.tokengovernancejava.web;

import com.github.h3yow.tokengovernancejava.credential.CredentialException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/** 把凭证错误映射为 403 响应，并在响应体中保留可区分的错误类型。 */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(CredentialException.class)
    public ResponseEntity<Map<String, String>> handleCredential(CredentialException e) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("errorType", e.getErrorType().name(), "message", e.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleIllegalArg(IllegalArgumentException e) {
        return ResponseEntity.badRequest()
                .body(Map.of("errorType", "BAD_REQUEST", "message", e.getMessage()));
    }
}

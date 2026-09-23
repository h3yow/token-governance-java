package com.github.h3yow.tokengovernancejava.web;

import com.github.h3yow.tokengovernancejava.authz.AuthorizationException;
import com.github.h3yow.tokengovernancejava.token.RejectionReason;
import com.github.h3yow.tokengovernancejava.token.TokenException;
import com.github.h3yow.tokengovernancejava.web.dto.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** 把领域异常映射为可区分错误码的 HTTP 响应。 */
@RestControllerAdvice
public class GovernanceExceptionHandler {

    @ExceptionHandler(TokenException.class)
    public ResponseEntity<ErrorResponse> handleToken(TokenException ex) {
        HttpStatus status = switch (ex.getReason()) {
            case NOT_FOUND, WRONG_TYPE -> HttpStatus.NOT_FOUND;
            case EXPIRED -> HttpStatus.GONE;
            case REVOKED -> HttpStatus.FORBIDDEN;
            case ALREADY_CONSUMED, REPLAY_DETECTED -> HttpStatus.CONFLICT;
        };
        // error 字段直接携带可区分的拒绝原因，便于调用方归因。
        return ResponseEntity.status(status)
                .body(new ErrorResponse(ex.getReason().name(), ex.getMessage()));
    }

    @ExceptionHandler(AuthorizationException.class)
    public ResponseEntity<ErrorResponse> handleAuthz(AuthorizationException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new ErrorResponse(ex.getDecision().code().name(), ex.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegal(IllegalArgumentException ex) {
        return ResponseEntity.badRequest()
                .body(new ErrorResponse("INVALID_REQUEST", ex.getMessage()));
    }
}

package com.github.h3yow.tokengovernancejava.web;

import com.github.h3yow.tokengovernancejava.authz.AuthorizationException;
import com.github.h3yow.tokengovernancejava.session.SessionException;
import com.github.h3yow.tokengovernancejava.session.SessionRejectionReason;
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
            case ALREADY_CONSUMED -> HttpStatus.CONFLICT;
            // 重放（会话泄露）与并发抢输区分：重放为 401（凭证已因泄露作废），
            // 并携带独立 error 码，调用方不会与“过期/不存在/类型错误”混淆。
            case REPLAY_DETECTED -> HttpStatus.UNAUTHORIZED;
        };
        // error 字段直接携带可区分的拒绝原因，便于调用方归因。
        return ResponseEntity.status(status)
                .body(new ErrorResponse(ex.getReason().name(), ex.getMessage()));
    }

    @ExceptionHandler(SessionException.class)
    public ResponseEntity<ErrorResponse> handleSession(SessionException ex) {
        HttpStatus status = ex.getReason() == SessionRejectionReason.SESSION_LIMIT_REACHED
                ? HttpStatus.CONFLICT : HttpStatus.NOT_FOUND;
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

package com.github.h3yow.tokengovernancejava.session;

/** 会话管理相关异常，携带可区分的拒绝原因。 */
public class SessionException extends RuntimeException {

    private final SessionRejectionReason reason;

    public SessionException(SessionRejectionReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public SessionRejectionReason getReason() {
        return reason;
    }
}

package com.github.h3yow.tokengovernancejava.session;

/** 会话相关异常，携带可区分的拒绝原因。 */
public class SessionException extends RuntimeException {

    private final SessionRejection reason;

    public SessionException(SessionRejection reason, String message) {
        super(message);
        this.reason = reason;
    }

    public SessionRejection getReason() {
        return reason;
    }
}

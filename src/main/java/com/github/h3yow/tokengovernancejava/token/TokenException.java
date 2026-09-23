package com.github.h3yow.tokengovernancejava.token;

/** 凭证相关异常，携带可区分的拒绝原因。 */
public class TokenException extends RuntimeException {

    private final RejectionReason reason;

    public TokenException(RejectionReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public RejectionReason getReason() {
        return reason;
    }
}

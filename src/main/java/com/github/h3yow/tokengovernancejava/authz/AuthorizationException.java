package com.github.h3yow.tokengovernancejava.authz;

/** 授权被拒绝时抛出，携带可解释的结论。 */
public class AuthorizationException extends RuntimeException {

    private final transient AuthorizationDecision decision;

    public AuthorizationException(AuthorizationDecision decision) {
        super(decision.reason());
        this.decision = decision;
    }

    public AuthorizationDecision getDecision() {
        return decision;
    }
}

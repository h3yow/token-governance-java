package com.github.h3yow.tokengovernancejava.authz;

/** 授权结论的可区分归类，配合判定依据逐条解释为何放行/拒绝。 */
public enum DecisionCode {
    PERMIT,
    DENY_EXPLICIT,
    DENY_NO_RULE,
    DENY_CONFLICT,
    DENY_SUBJECT_NOT_FOUND
}

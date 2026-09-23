package com.github.h3yow.tokengovernancejava.web.dto;

import com.github.h3yow.tokengovernancejava.authz.AuthorizationDecision;

/** 授权判定响应（含可解释依据）。 */
public record CheckResponse(boolean permitted,
                            String code,
                            String reason,
                            Object trace) {

    public static CheckResponse from(AuthorizationDecision d) {
        return new CheckResponse(d.permitted(), d.code().name(), d.reason(), d.trace());
    }
}

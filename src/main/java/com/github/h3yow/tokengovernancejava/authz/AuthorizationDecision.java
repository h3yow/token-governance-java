package com.github.h3yow.tokengovernancejava.authz;

import java.util.List;

/**
 * 可解释的授权结论。
 *
 * @param permitted 是否放行
 * @param code      结论归类
 * @param reason    人类可读的总体说明
 * @param trace     逐条判定依据
 */
public record AuthorizationDecision(boolean permitted,
                                    DecisionCode code,
                                    String reason,
                                    List<DecisionTrace> trace) {

    public AuthorizationDecision {
        trace = List.copyOf(trace);
    }
}

package com.github.h3yow.tokengovernancejava.authz;

/**
 * 单条判定依据：由哪条规则（或何种原因）导致了当前结论。
 */
public record DecisionReason(
        DecisionReasonCode code,
        RuleKind kind,
        String ruleId,
        String detail
) {
    public static DecisionReason of(DecisionReasonCode code, String detail) {
        return new DecisionReason(code, null, null, detail);
    }
}

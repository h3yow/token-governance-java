package com.github.h3yow.tokengovernancejava.authz;

/**
 * 授权结论的原因代码，保证"为什么放行/拒绝"可解释。
 */
public enum DecisionReasonCode {

    /** 命中显式拒绝规则（拒绝优先）。 */
    EXPLICIT_DENY_RULE,

    /** 命中显式允许规则且无任何拒绝规则适用。 */
    EXPLICIT_ALLOW_RULE,

    /** 同时存在适用的允许与拒绝规则，按"拒绝优先"处理。 */
    CONFLICT_DENY_WINS,

    /** 没有任何规则适用，默认拒绝。 */
    NO_APPLICABLE_RULE,

    /** 主体不存在，拒绝。 */
    SUBJECT_MISSING,

    /** 凭证无效（过期/吊销/版本过期等），拒绝。 */
    CREDENTIAL_INVALID
}

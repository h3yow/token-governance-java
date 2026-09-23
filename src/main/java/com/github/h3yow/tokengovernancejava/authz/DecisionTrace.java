package com.github.h3yow.tokengovernancejava.authz;

/**
 * 判定依据中的一条：某规则是否命中及其效力。
 *
 * @param ruleId  规则标识
 * @param matched 是否命中
 * @param effect  规则效力
 * @param detail  人类可读的解释
 */
public record DecisionTrace(String ruleId, boolean matched, Effect effect, String detail) {
}

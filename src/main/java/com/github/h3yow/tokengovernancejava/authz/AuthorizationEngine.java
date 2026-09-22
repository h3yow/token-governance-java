package com.github.h3yow.tokengovernancejava.authz;

/**
 * 纯授权判定引擎：依据主体角色/属性与策略规则给出可解释结论。
 * 显式拒绝优先于允许，规则缺失或冲突时默认拒绝，绝不静默放行。
 */
public interface AuthorizationEngine {

    Decision evaluate(Subject subject, AuthzRequest request);
}

package com.github.h3yow.tokengovernancejava.authz;

/**
 * 授权入口：组合"凭证校验 → 主体/版本实时检查 → 策略判定"。
 */
public interface AuthorizationGateway {

    Decision authorize(String accessToken, AuthzRequest request);
}

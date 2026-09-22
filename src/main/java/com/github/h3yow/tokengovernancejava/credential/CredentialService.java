package com.github.h3yow.tokengovernancejava.credential;

/**
 * 访问凭证签发、刷新旋转、吊销与解析的核心服务。
 */
public interface CredentialService {

    /** 为主体签发一对全新凭证，stampedVersion 为主体当前权限版本。 */
    TokenPair issue(String subjectId, long stampedVersion);

    /**
     * 使用刷新凭证旋转出新凭证对。
     * 同一刷新凭证并发使用时至多成功一次；已消费/过期/吊销均以
     * {@link CredentialException} 的明确错误类型拒绝。
     */
    TokenPair refresh(String refreshToken);

    /** 解析并校验访问凭证（签名、过期、会话与版本状态）。 */
    AccessCredential introspect(String accessToken);

    /** 吊销整个凭证族（会话）。 */
    void revokeFamily(String familyId);

    /** 吊销某主体的全部凭证族。 */
    void revokeAllForSubject(String subjectId);
}

package com.github.h3yow.tokengovernancejava.credential;

import java.time.Instant;

/**
 * 访问凭证解析后的可信内容（签名与状态校验通过后才会产生）。
 */
public record AccessCredential(
        String subjectId,
        String familyId,
        long version,
        String jti,
        Instant expiresAt
) {
}

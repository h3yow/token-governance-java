package com.github.h3yow.tokengovernancejava.credential;

import java.time.Instant;

/**
 * 一次签发或旋转成功后返回的凭证对。
 *
 * @param familyId              凭证族（会话）标识，同一族内的刷新旋转共享吊销状态
 * @param version               签发时主体的权限版本，主体权限变更后旧版本凭证失效
 * @param accessToken           访问凭证
 * @param refreshToken          刷新凭证（一次性，旋转后旧凭证立即失效）
 * @param accessTokenExpiresAt  访问凭证过期时刻
 * @param refreshTokenExpiresAt 刷新凭证过期时刻
 */
public record TokenPair(
        String subjectId,
        String familyId,
        long version,
        String accessToken,
        String refreshToken,
        Instant accessTokenExpiresAt,
        Instant refreshTokenExpiresAt
) {
}

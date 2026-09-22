package com.github.h3yow.tokengovernancejava.authz;

/**
 * 一次授权判定的输入。
 *
 * @param subjectId 主体标识
 * @param action    待执行动作，如 document:read
 * @param resource  目标资源，支持精确串或 a/b/* 形式前缀
 */
public record AuthzRequest(
        String subjectId,
        String action,
        String resource
) {
}

package com.github.h3yow.tokengovernancejava.token;

/**
 * 访问凭证校验结果。
 *
 * @param subject 凭证主体
 * @param token   通过校验的访问凭证
 */
public record AccessValidation(String subject, Token token) {
}

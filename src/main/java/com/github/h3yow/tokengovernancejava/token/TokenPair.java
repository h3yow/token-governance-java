package com.github.h3yow.tokengovernancejava.token;

/** 一次签发或旋转成功后返回的新凭证对。 */
public record TokenPair(Token accessToken, Token refreshToken) {
}

package com.github.h3yow.tokengovernancejava.web.dto;

/** 授权判定请求。 */
public record CheckRequest(String accessToken, String action, String resource) {
}

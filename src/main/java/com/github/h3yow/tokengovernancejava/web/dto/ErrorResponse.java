package com.github.h3yow.tokengovernancejava.web.dto;

/** 统一错误响应，error 为可区分的错误归类。 */
public record ErrorResponse(String error, String message) {
}

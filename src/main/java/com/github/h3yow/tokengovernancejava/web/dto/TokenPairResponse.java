package com.github.h3yow.tokengovernancejava.web.dto;

/** 凭证对响应。 */
public record TokenPairResponse(String accessToken,
                                String refreshToken,
                                long accessExpiresAt,
                                long refreshExpiresAt) {
}

package com.github.h3yow.tokengovernancejava.web.dto;

/**
 * 凭证对响应。
 *
 * @param sessionId 本次签发/旋转所属会话标识，可用于会话清单与按会话下线
 */
public record TokenPairResponse(String accessToken,
                                String refreshToken,
                                long accessExpiresAt,
                                long refreshExpiresAt,
                                String sessionId) {
}

package com.github.h3yow.tokengovernancejava.web.dto;

/**
 * 凭证对响应。
 *
 * @param sessionId 该凭证所属登录会话（设备）标识，便于做会话查看/下线
 */
public record TokenPairResponse(String accessToken,
                                String refreshToken,
                                long accessExpiresAt,
                                long refreshExpiresAt,
                                String sessionId) {
}

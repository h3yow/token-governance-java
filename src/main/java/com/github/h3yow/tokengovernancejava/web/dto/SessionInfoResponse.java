package com.github.h3yow.tokengovernancejava.web.dto;

import com.github.h3yow.tokengovernancejava.session.SessionInfo;

/**
 * 会话清单项：仅会话标识与元信息，不包含任何凭证。
 */
public record SessionInfoResponse(String sessionId,
                                  String subject,
                                  String deviceLabel,
                                  long createdAt,
                                  long lastRefreshedAt,
                                  long expiresAt) {

    public static SessionInfoResponse from(SessionInfo info) {
        return new SessionInfoResponse(info.sessionId(), info.subject(), info.deviceLabel(),
                info.createdAt(), info.lastRefreshedAt(), info.expiresAt());
    }
}

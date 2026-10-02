package com.github.h3yow.tokengovernancejava.session;

/**
 * 会话清单对外视图：只暴露会话标识与元信息，绝不携带任何凭证。
 *
 * @param sessionId       会话标识（等于其凭证家族 id）
 * @param subject         会话所属用户
 * @param deviceLabel     签发时携带的设备/来源标识（老调用方式为 default）
 * @param createdAt       会话建立时间（毫秒）
 * @param lastRefreshedAt 最近一次刷新时间（毫秒，未刷新过等于建立时间）
 * @param expiresAt       当前刷新凭证到期时间（毫秒），会话随之到期
 * @param expired         查询时刻是否已到期
 */
public record SessionView(String sessionId,
                          String subject,
                          String deviceLabel,
                          long createdAt,
                          long lastRefreshedAt,
                          long expiresAt,
                          boolean expired) {
}

package com.github.h3yow.tokengovernancejava.session;

/**
 * 会话清单中对外暴露的会话元信息（绝不包含凭证本身）。
 *
 * @param sessionId       会话标识（与该会话首个刷新家族 id 相同）
 * @param subject         会话所属主体
 * @param deviceLabel     设备/来源标识；老调用不带时为默认标识
 * @param createdAt       建立时间（epoch 毫秒）
 * @param lastRefreshedAt 最近一次成功旋转时间；从未旋转时等于建立时间
 * @param expiresAt       当前生效刷新凭证的到期时间（epoch 毫秒）
 */
public record SessionInfo(String sessionId,
                          String subject,
                          String deviceLabel,
                          long createdAt,
                          long lastRefreshedAt,
                          long expiresAt) {
}

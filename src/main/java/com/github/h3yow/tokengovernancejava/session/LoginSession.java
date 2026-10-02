package com.github.h3yow.tokengovernancejava.session;

import java.util.concurrent.atomic.AtomicReference;

/**
 * 一次登录会话（一台设备/一个来源）。
 *
 * <p>会话与凭证家族（family）一一对应：会话 id 即 familyId。会话存续期间，
 * 刷新旋转在同一家族内换代；会话结束时整族凭证立即失效。</p>
 *
 * <p>时间单位均为毫秒。状态用 {@link AtomicReference} 持有，结束操作是
 * ACTIVE -> ENDED 的一次性原子跃迁。</p>
 */
public final class LoginSession {

    private final String id;
    private final String subject;
    private final String deviceLabel;
    private final long createdAt;
    private volatile long lastRefreshedAt;
    private volatile long refreshExpiresAt;
    private final AtomicReference<SessionState> state;

    public LoginSession(String id, String subject, String deviceLabel,
                        long createdAt, long refreshExpiresAt) {
        this.id = id;
        this.subject = subject;
        this.deviceLabel = deviceLabel;
        this.createdAt = createdAt;
        this.lastRefreshedAt = createdAt;
        this.refreshExpiresAt = refreshExpiresAt;
        this.state = new AtomicReference<>(SessionState.ACTIVE);
    }

    public String getId() {
        return id;
    }

    public String getSubject() {
        return subject;
    }

    public String getDeviceLabel() {
        return deviceLabel;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public long getLastRefreshedAt() {
        return lastRefreshedAt;
    }

    public long getRefreshExpiresAt() {
        return refreshExpiresAt;
    }

    public SessionState getState() {
        return state.get();
    }

    /** 仅当当前状态等于 expected 时原子地更新为 update。 */
    public boolean casState(SessionState expected, SessionState update) {
        return state.compareAndSet(expected, update);
    }

    /** 旋转成功后刷新会话元信息（仅 ACTIVE 时生效）。 */
    public void recordRotation(long refreshedAt, long newRefreshExpiresAt) {
        if (getState() == SessionState.ACTIVE) {
            this.lastRefreshedAt = refreshedAt;
            this.refreshExpiresAt = newRefreshExpiresAt;
        }
    }

    /** 生成对外视图（不暴露任何凭证）。 */
    public SessionView toView(long now) {
        return new SessionView(id, subject, deviceLabel, createdAt,
                lastRefreshedAt, refreshExpiresAt, now >= refreshExpiresAt);
    }
}

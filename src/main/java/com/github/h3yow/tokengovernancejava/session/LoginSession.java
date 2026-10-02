package com.github.h3yow.tokengovernancejava.session;

import java.util.concurrent.atomic.AtomicReference;

/**
 * 一次登录会话（对应一个设备/来源）。
 *
 * <p>一个会话在其生命周期内始终对应<b>同一个刷新家族</b>：会话标识即首次签发时的
 * {@code familyId}，后续旋转延续该家族。因此结束会话 = 吊销其刷新家族。</p>
 *
 * <p>会话元信息（最近刷新时间、当前到期时间）会在每次成功旋转后更新；
 * 会话状态用 {@link AtomicReference} 持有。</p>
 */
public final class LoginSession {

    private final String sessionId;
    private final String subject;
    private final String deviceLabel;
    private final long createdAt;
    private final long creationSeq;
    private final AtomicReference<SessionState> state = new AtomicReference<>(SessionState.ACTIVE);

    private volatile long lastRefreshedAt;
    private volatile long expiresAt;

    public LoginSession(String sessionId, String subject, String deviceLabel,
                        long createdAt, long creationSeq, long expiresAt) {
        this.sessionId = sessionId;
        this.subject = subject;
        this.deviceLabel = deviceLabel;
        this.createdAt = createdAt;
        this.creationSeq = creationSeq;
        this.lastRefreshedAt = createdAt;
        this.expiresAt = expiresAt;
    }

    public String getSessionId() {
        return sessionId;
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

    /** 单调创建序号：同一毫秒内多次签发时用于稳定排序。 */
    public long getCreationSeq() {
        return creationSeq;
    }

    public long getLastRefreshedAt() {
        return lastRefreshedAt;
    }

    public long getExpiresAt() {
        return expiresAt;
    }

    public SessionState getState() {
        return state.get();
    }

    public boolean isActive() {
        return state.get() == SessionState.ACTIVE;
    }

    /** 一次成功旋转后更新会话元信息：最近刷新时间与当前刷新凭证到期时间。 */
    public void touch(long refreshedAt, long newExpiresAt) {
        this.lastRefreshedAt = refreshedAt;
        this.expiresAt = newExpiresAt;
    }

    /** 结束会话（幂等：重复结束返回 false）。 */
    public boolean end() {
        return state.compareAndSet(SessionState.ACTIVE, SessionState.ENDED);
    }

    /** 对外清单视图：仅含会话标识与元信息，不含任何凭证。 */
    public SessionInfo toInfo() {
        return new SessionInfo(sessionId, subject, deviceLabel,
                createdAt, lastRefreshedAt, expiresAt);
    }
}

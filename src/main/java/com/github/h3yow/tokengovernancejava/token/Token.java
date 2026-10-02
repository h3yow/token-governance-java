package com.github.h3yow.tokengovernancejava.token;

import java.util.concurrent.atomic.AtomicReference;

/**
 * 单个凭证（访问凭证或刷新凭证）。
 *
 * <p>时间单位均为毫秒（System.currentTimeMillis 语义）。
 * 刷新凭证通过 familyId 形成旋转家族：旋转出新凭证后，旧凭证被标记 CONSUMED；
 * 家族内任一成员被吊销时，整个家族一并失效。</p>
 *
 * <p>状态用 {@link AtomicReference} 持有，保证 ACTIVE -> CONSUMED 的旋转消费
 * 在并发下只有一个线程成功（CAS）。</p>
 */
public final class Token {

    private final String id;
    private final TokenType type;
    private final String subject;
    private final String familyId;
    private final long issuedAt;
    private final long expiresAt;
    private final AtomicReference<TokenState> state;
    /** 被消费（旋转成功）的时刻；-1 表示尚未消费。用于区分并发抢输与事后重放。 */
    private volatile long consumedAt = -1L;

    public Token(String id, TokenType type, String subject, String familyId,
                 long issuedAt, long expiresAt, TokenState state) {
        this.id = id;
        this.type = type;
        this.subject = subject;
        this.familyId = familyId;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.state = new AtomicReference<>(state);
    }

    public String getId() {
        return id;
    }

    public TokenType getType() {
        return type;
    }

    public String getSubject() {
        return subject;
    }

    public String getFamilyId() {
        return familyId;
    }

    public long getIssuedAt() {
        return issuedAt;
    }

    public long getExpiresAt() {
        return expiresAt;
    }

    public TokenState getState() {
        return state.get();
    }

    public void setState(TokenState newState) {
        state.set(newState);
    }

    /**
     * 仅当当前状态等于 expected 时原子地更新为 update。
     * 用于并发旋转时 ACTIVE -> CONSUMED 的抢占，保证同一刷新凭证最多成功一次。
     */
    public boolean casState(TokenState expected, TokenState update) {
        return state.compareAndSet(expected, update);
    }

    /** 被消费的时刻（毫秒），未消费为 -1。 */
    public long getConsumedAt() {
        return consumedAt;
    }

    /** 记录消费时刻；须在持有家族锁的旋转临界区内调用。 */
    public void markConsumed(long consumedAtMillis) {
        this.consumedAt = consumedAtMillis;
    }
}

package com.github.h3yow.tokengovernancejava.session;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 会话注册表：线程安全地保存全部会话，并按用户索引。
 *
 * <p>负责：建立会话（含每用户有效会话数上限）、查询有效会话、
 * 记录旋转、结束会话（一次性原子跃迁）。</p>
 *
 * <p>“有效会话”指未结束且当前刷新凭证尚未到期的会话；已到上限时
 * 明确抛出 {@link SessionRejection#SESSION_LIMIT_EXCEEDED}，
 * 绝不悄悄挤掉旧会话，也不放任数量无限增长。</p>
 */
public class SessionRegistry {

    /** 老调用方式（未携带设备信息）使用的默认来源标识。 */
    public static final String DEFAULT_DEVICE_LABEL = "default";

    private final int maxActivePerSubject;
    private final Clock clock;

    private final Map<String, LoginSession> sessions = new ConcurrentHashMap<>();
    private final Map<String, ConcurrentHashMap.KeySetView<String, Boolean>> bySubject =
            new ConcurrentHashMap<>();

    public SessionRegistry(int maxActivePerSubject, Clock clock) {
        if (maxActivePerSubject <= 0) {
            throw new IllegalArgumentException("每用户会话上限必须为正");
        }
        this.maxActivePerSubject = maxActivePerSubject;
        this.clock = clock;
    }

    public int maxActivePerSubject() {
        return maxActivePerSubject;
    }

    private long now() {
        return clock.millis();
    }

    /**
     * 建立会话。同一用户的有效会话数达到上限时明确拒绝。
     *
     * <p>计数与登记在同一个用户级临界区内完成，并发签发不会突破上限。</p>
     *
     * @throws SessionException 原因 {@link SessionRejection#SESSION_LIMIT_EXCEEDED}
     */
    public LoginSession create(String subject, String deviceLabel, String sessionId,
                               long createdAt, long refreshExpiresAt) {
        String label = (deviceLabel == null || deviceLabel.isBlank())
                ? DEFAULT_DEVICE_LABEL : deviceLabel;
        LoginSession session =
                new LoginSession(sessionId, subject, label, createdAt, refreshExpiresAt);
        // 按用户加锁：上限校验与登记必须原子，否则并发签发会越过上限。
        synchronized (lockFor(subject)) {
            int active = countEffective(subject);
            if (active >= maxActivePerSubject) {
                throw new SessionException(SessionRejection.SESSION_LIMIT_EXCEEDED,
                        "用户 " + subject + " 的有效会话数已达上限 " + maxActivePerSubject
                                + "，请先结束其它会话");
            }
            sessions.put(sessionId, session);
            bySubject.computeIfAbsent(subject, k -> ConcurrentHashMap.newKeySet())
                    .add(sessionId);
        }
        return session;
    }

    /** 按 id 查找会话（含已结束会话），不存在返回 null。 */
    public LoginSession get(String sessionId) {
        return sessions.get(sessionId);
    }

    /** 列出某用户当前未结束会话的对外视图（含到期标志，不含任何凭证）。 */
    public List<SessionView> listViews(String subject) {
        List<SessionView> views = new ArrayList<>();
        for (LoginSession s : activeSessionsOf(subject)) {
            views.add(s.toView(now()));
        }
        return views;
    }

    /**
     * 结束会话：ACTIVE -> ENDED 的一次性原子跃迁。
     *
     * @return true 表示由本次调用完成跃迁；false 表示会话不存在或已结束
     */
    public boolean markEnded(String sessionId) {
        LoginSession session = sessions.get(sessionId);
        return session != null && session.casState(SessionState.ACTIVE, SessionState.ENDED);
    }

    /** 旋转成功后更新会话元信息（会话已结束时为空操作）。 */
    public void recordRotation(String sessionId, long refreshedAt, long refreshExpiresAt) {
        LoginSession session = sessions.get(sessionId);
        if (session != null) {
            session.recordRotation(refreshedAt, refreshExpiresAt);
        }
    }

    /** 某用户当前所有未结束会话。 */
    public List<LoginSession> activeSessionsOf(String subject) {
        List<LoginSession> result = new ArrayList<>();
        var ids = bySubject.get(subject);
        if (ids == null) {
            return result;
        }
        for (String id : ids) {
            LoginSession s = sessions.get(id);
            if (s != null && s.getState() == SessionState.ACTIVE) {
                result.add(s);
            }
        }
        return result;
    }

    /** 有效会话数：未结束且当前刷新凭证尚未到期。 */
    private int countEffective(String subject) {
        int count = 0;
        long now = now();
        for (LoginSession s : activeSessionsOf(subject)) {
            if (now < s.getRefreshExpiresAt()) {
                count++;
            }
        }
        return count;
    }

    private Object lockFor(String subject) {
        // 复用 bySubject 的槽位作为用户级锁，避免再维护一把锁表。
        return bySubject.computeIfAbsent(subject, k -> ConcurrentHashMap.newKeySet());
    }
}

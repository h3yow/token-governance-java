package com.github.h3yow.tokengovernancejava.session;

import com.github.h3yow.tokengovernancejava.token.TokenService;

import java.util.List;

/**
 * 会话管理服务：查看会话清单、按会话精细下线、按用户整体下线。
 *
 * <p>结束会话时通过 {@link TokenService} 吊销该会话对应的整个凭证家族，
 * 使该会话名下已发出的全部凭证（含最近一次旋转换出的访问凭证）立即失效，
 * 且不影响该用户的其它会话。</p>
 *
 * <p>结束与旋转的并发由家族锁串行化：要么旋转先完成、随后整族（含新凭证）
 * 被吊销；要么结束先生效、旋转因凭证已吊销而被拒绝。两种交错下都不会出现
 * “会话已结束却仍返回可用新凭证”，也不会出现“结束未真正生效”。</p>
 */
public class SessionService {

    private final SessionRegistry registry;
    private final TokenService tokenService;

    public SessionService(SessionRegistry registry, TokenService tokenService) {
        this.registry = registry;
        this.tokenService = tokenService;
    }

    /** 查看某用户当前有效（未结束）会话清单；只含元信息，不含任何凭证。 */
    public List<SessionView> listSessions(String subject) {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject 不能为空");
        }
        return registry.listViews(subject);
    }

    /**
     * 单独结束某个会话，立即生效；不影响该用户的其它会话。
     *
     * @throws SessionException 会话不存在或已结束时如实报错
     *         （{@link SessionRejection#SESSION_NOT_FOUND}）
     */
    public void endSession(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            throw new IllegalArgumentException("sessionId 不能为空");
        }
        // 原子跃迁保证并发结束只有一个生效；未跃迁成功说明不存在或已结束。
        if (!registry.markEnded(sessionId)) {
            throw new SessionException(SessionRejection.SESSION_NOT_FOUND,
                    "会话不存在或已结束: " + sessionId);
        }
        // 吊销整族（与旋转互斥）：该会话名下全部凭证立即失效。
        tokenService.revokeFamilyById(sessionId);
    }

    /**
     * 结束某用户的全部会话，返回实际结束的会话数。
     * 用户不存在或没有有效会话时返回 0（整体下线是幂等语义）。
     */
    public int endAllSessions(String subject) {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject 不能为空");
        }
        int ended = 0;
        for (LoginSession session : registry.activeSessionsOf(subject)) {
            if (registry.markEnded(session.getId())) {
                tokenService.revokeFamilyById(session.getId());
                ended++;
            }
        }
        return ended;
    }
}

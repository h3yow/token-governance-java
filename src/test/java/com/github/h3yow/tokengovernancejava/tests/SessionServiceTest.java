package com.github.h3yow.tokengovernancejava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.tokengovernancejava.session.LoginSession;
import com.github.h3yow.tokengovernancejava.session.SessionException;
import com.github.h3yow.tokengovernancejava.session.SessionRegistry;
import com.github.h3yow.tokengovernancejava.session.SessionRejection;
import com.github.h3yow.tokengovernancejava.session.SessionService;
import com.github.h3yow.tokengovernancejava.session.SessionView;
import com.github.h3yow.tokengovernancejava.token.RejectionReason;
import com.github.h3yow.tokengovernancejava.token.TokenException;
import com.github.h3yow.tokengovernancejava.token.TokenPair;
import com.github.h3yow.tokengovernancejava.token.TokenService;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 登录会话（设备）管理测试：多会话并存、按会话/按用户下线、
 * 重放按会话泄露处理、结束与刷新并发竞态、会话数上限。
 * 每个用例都打印输入与判定依据。
 */
class SessionServiceTest {

    private static final Logger log = LoggerFactory.getLogger(SessionServiceTest.class);

    private static final long ACCESS_TTL = 60_000L;
    private static final long REFRESH_TTL = 300_000L;
    private static final long SKEW = 30_000L;
    private static final long REPLAY_GRACE = 10_000L;
    private static final long T0 = 1_000_000L;

    /** 测试装配：可变时钟 + 会话注册表 + 凭证服务 + 会话服务。 */
    private record Rig(MutableClock clock, TokenService tokens, SessionService sessions) {
    }

    private Rig rig(int maxSessionsPerSubject) {
        MutableClock clock = new MutableClock(T0);
        SessionRegistry registry = new SessionRegistry(maxSessionsPerSubject, clock);
        TokenService tokens = new TokenService(ACCESS_TTL, REFRESH_TTL, SKEW,
                REPLAY_GRACE, registry, clock);
        return new Rig(clock, tokens, new SessionService(registry, tokens));
    }

    private void expectTokenReject(RejectionReason reason, Runnable action) {
        TokenException ex = assertThrows(TokenException.class, action::run);
        assertEquals(reason, ex.getReason(),
                "拒绝原因应为 " + reason + "，实际 " + ex.getReason());
    }

    @Test
    void multiple_sessions_coexist_and_rotate_independently() {
        Rig rig = rig(5);
        TokenPair phone = rig.tokens().issue("alice", "phone");
        TokenPair tablet = rig.tokens().issue("alice", "tablet");
        TokenPair pc = rig.tokens().issue("alice", "pc");
        log.info("[多会话] alice 建立 3 个会话 phone/tablet/pc");

        List<SessionView> views = rig.sessions().listSessions("alice");
        assertEquals(3, views.size(), "应看到 3 个有效会话");
        for (SessionView v : views) {
            log.info("[多会话] 清单 session={} device={} createdAt={} lastRefreshedAt={} expiresAt={} expired={}",
                    v.sessionId(), v.deviceLabel(), v.createdAt(),
                    v.lastRefreshedAt(), v.expiresAt(), v.expired());
            assertEquals("alice", v.subject());
            assertEquals(T0, v.createdAt());
            assertEquals(T0 + REFRESH_TTL, v.expiresAt());
            assertFalse(v.expired());
        }

        // phone 旋转：只推进 phone 会话的元信息，其它会话不受影响。
        rig.clock().advanceMillis(5_000L);
        TokenPair phone2 = rig.tokens().rotate(phone.refreshToken().getId());
        log.info("[多会话] phone 旋转成功 新access={}", phone2.accessToken().getId());

        SessionView phoneView = rig.sessions().listSessions("alice").stream()
                .filter(v -> v.deviceLabel().equals("phone")).findFirst().orElseThrow();
        assertEquals(T0 + 5_000L, phoneView.lastRefreshedAt(), "最近刷新时间应随旋转更新");
        assertEquals(T0 + 5_000L + REFRESH_TTL, phoneView.expiresAt(), "到期时间应随旋转顺延");
        log.info("[多会话] phone 旋转后 lastRefreshedAt={} expiresAt={}",
                phoneView.lastRefreshedAt(), phoneView.expiresAt());

        // 其它会话的凭证照常可用。
        assertEquals("alice", rig.tokens().validateAccess(tablet.accessToken().getId()).subject());
        assertEquals("alice", rig.tokens().validateAccess(pc.accessToken().getId()).subject());
        log.info("[多会话] tablet/pc 会话不受影响，访问凭证均校验通过");
    }

    @Test
    void legacy_issue_without_device_uses_default_session() {
        Rig rig = rig(5);
        // 老调用方式：不传设备标识。
        TokenPair pair = rig.tokens().issue("bob");
        List<SessionView> views = rig.sessions().listSessions("bob");
        assertEquals(1, views.size());
        assertEquals(SessionRegistry.DEFAULT_DEVICE_LABEL, views.get(0).deviceLabel());
        log.info("[兼容] 老调用方式签发 => 默认会话 device={} session={}",
                views.get(0).deviceLabel(), views.get(0).sessionId());
        assertEquals("bob", rig.tokens().validateAccess(pair.accessToken().getId()).subject());
    }

    @Test
    void session_listing_never_exposes_tokens() throws Exception {
        Rig rig = rig(5);
        TokenPair pair = rig.tokens().issue("carol", "phone");
        List<SessionView> views = rig.sessions().listSessions("carol");
        String json = new ObjectMapper().writeValueAsString(views);
        log.info("[清单] 序列化结果={}", json);
        assertFalse(json.contains(pair.accessToken().getId()), "清单不得暴露访问凭证");
        assertFalse(json.contains(pair.refreshToken().getId()), "清单不得暴露刷新凭证");
        assertTrue(json.contains(views.get(0).sessionId()), "清单应包含会话标识");
    }

    @Test
    void end_single_session_kills_its_tokens_but_not_others() {
        Rig rig = rig(5);
        TokenPair phone = rig.tokens().issue("dave", "phone");
        TokenPair tablet = rig.tokens().issue("dave", "tablet");
        // phone 先旋转一次，拿到“刚换出来、还很新”的访问凭证。
        TokenPair phone2 = rig.tokens().rotate(phone.refreshToken().getId());
        String phoneSession = phone2.accessToken().getFamilyId();
        log.info("[单会话下线] 结束 phone 会话 session={}", phoneSession);

        rig.sessions().endSession(phoneSession);

        // phone 会话名下所有凭证立即失效，包括刚旋转换出的新 access。
        expectTokenReject(RejectionReason.REVOKED,
                () -> rig.tokens().validateAccess(phone2.accessToken().getId()));
        expectTokenReject(RejectionReason.REVOKED,
                () -> rig.tokens().rotate(phone2.refreshToken().getId()));
        expectTokenReject(RejectionReason.REVOKED,
                () -> rig.tokens().validateAccess(phone.accessToken().getId()));
        log.info("[单会话下线] phone 的新旧 access/refresh 全部立即失效 reason=REVOKED");

        // tablet 会话完全不受影响。
        assertEquals("dave", rig.tokens().validateAccess(tablet.accessToken().getId()).subject());
        TokenPair tablet2 = rig.tokens().rotate(tablet.refreshToken().getId());
        assertEquals("dave", rig.tokens().validateAccess(tablet2.accessToken().getId()).subject());
        log.info("[单会话下线] tablet 会话校验与旋转均正常");

        List<SessionView> views = rig.sessions().listSessions("dave");
        assertEquals(1, views.size());
        assertEquals("tablet", views.get(0).deviceLabel());
        log.info("[单会话下线] 剩余会话清单={}", views);
    }

    @Test
    void end_all_sessions_of_a_subject() {
        Rig rig = rig(5);
        TokenPair a = rig.tokens().issue("erin", "phone");
        TokenPair b = rig.tokens().issue("erin", "tablet");
        TokenPair other = rig.tokens().issue("fiona", "pc");

        int ended = rig.sessions().endAllSessions("erin");
        log.info("[全部下线] erin 结束会话数={}", ended);
        assertEquals(2, ended);
        assertTrue(rig.sessions().listSessions("erin").isEmpty());

        expectTokenReject(RejectionReason.REVOKED,
                () -> rig.tokens().validateAccess(a.accessToken().getId()));
        expectTokenReject(RejectionReason.REVOKED,
                () -> rig.tokens().rotate(b.refreshToken().getId()));
        log.info("[全部下线] erin 两个会话的凭证全部失效");

        // 其它用户不受影响。
        assertEquals("fiona", rig.tokens().validateAccess(other.accessToken().getId()).subject());
        assertEquals(0, rig.sessions().endAllSessions("erin"), "重复整体下线应返回 0");
        log.info("[全部下线] fiona 会话不受影响；重复整体下线返回 0");
    }

    @Test
    void ending_unknown_session_is_reported_not_silent_success() {
        Rig rig = rig(5);
        SessionException ex = assertThrows(SessionException.class,
                () -> rig.sessions().endSession("ghost-session"));
        assertEquals(SessionRejection.SESSION_NOT_FOUND, ex.getReason());
        log.info("[不存在] 结束未知会话 reason={} msg={}", ex.getReason(), ex.getMessage());

        // 已结束的会话再次结束也要如实报错。
        TokenPair pair = rig.tokens().issue("gina", "phone");
        String sessionId = pair.accessToken().getFamilyId();
        rig.sessions().endSession(sessionId);
        SessionException ex2 = assertThrows(SessionException.class,
                () -> rig.sessions().endSession(sessionId));
        assertEquals(SessionRejection.SESSION_NOT_FOUND, ex2.getReason());
        log.info("[不存在] 重复结束同一会话 reason={} msg={}", ex2.getReason(), ex2.getMessage());
    }

    @Test
    void replayed_refresh_kills_whole_session_including_rotated_tokens() {
        Rig rig = rig(5);
        TokenPair first = rig.tokens().issue("henry", "laptop");
        String oldRefresh = first.refreshToken().getId();

        // 正常旋转一次，换出一对“还很新”的凭证。
        TokenPair second = rig.tokens().rotate(oldRefresh);
        log.info("[重放] 首次旋转成功 新access={} 新refresh={}",
                second.accessToken().getId(), second.refreshToken().getId());
        assertEquals("henry", rig.tokens().validateAccess(second.accessToken().getId()).subject());

        // 宽窗口之后，旧刷新凭证再次出现 => 判定重放（疑似泄露）。
        rig.clock().advanceMillis(REPLAY_GRACE + 1L);
        TokenException ex = assertThrows(TokenException.class, () -> rig.tokens().rotate(oldRefresh));
        assertEquals(RejectionReason.REPLAY_DETECTED, ex.getReason());
        log.info("[重放] 旧 refresh 在宽窗口后再次出现 reason={} msg={}", ex.getReason(), ex.getMessage());

        // 整个会话作废：上次旋转换出的新 access / 新 refresh 也立即失效。
        expectTokenReject(RejectionReason.REVOKED,
                () -> rig.tokens().validateAccess(second.accessToken().getId()));
        expectTokenReject(RejectionReason.REVOKED,
                () -> rig.tokens().rotate(second.refreshToken().getId()));
        assertTrue(rig.sessions().listSessions("henry").isEmpty(), "会话应已整体作废");
        log.info("[重放] 新 access/新 refresh 均失效 reason=REVOKED，会话清单已空");

        // 拒绝原因可与不存在/类型错误/过期区分。
        assertTrue(ex.getReason() != RejectionReason.NOT_FOUND
                && ex.getReason() != RejectionReason.WRONG_TYPE
                && ex.getReason() != RejectionReason.EXPIRED
                && ex.getReason() != RejectionReason.ALREADY_CONSUMED);
    }

    @Test
    void consumed_within_grace_window_is_not_treated_as_replay() {
        Rig rig = rig(5);
        TokenPair first = rig.tokens().issue("ivan", "phone");
        String oldRefresh = first.refreshToken().getId();
        TokenPair second = rig.tokens().rotate(oldRefresh);

        // 宽窗口内再次使用（等价于并发抢输的时序）：报 ALREADY_CONSUMED，不株连会话。
        rig.clock().advanceMillis(REPLAY_GRACE - 1L);
        TokenException ex = assertThrows(TokenException.class, () -> rig.tokens().rotate(oldRefresh));
        assertEquals(RejectionReason.ALREADY_CONSUMED, ex.getReason());
        assertEquals("ivan", rig.tokens().validateAccess(second.accessToken().getId()).subject());
        assertEquals(1, rig.sessions().listSessions("ivan").size());
        log.info("[宽窗口] 窗口内的再次使用 reason={}，会话与新凭证不受影响", ex.getReason());
    }

    @Test
    void end_session_racing_rotate_never_leaves_usable_tokens() throws Exception {
        for (int round = 0; round < 100; round++) {
            Rig rig = rig(5);
            TokenPair pair = rig.tokens().issue("judy", "phone");
            String refresh = pair.refreshToken().getId();
            String sessionId = pair.accessToken().getFamilyId();
            AtomicReference<TokenPair> rotated = new AtomicReference<>();
            AtomicReference<TokenException> rotateError = new AtomicReference<>();

            Thread rotator = new Thread(() -> {
                try {
                    rotated.set(rig.tokens().rotate(refresh));
                } catch (TokenException ex) {
                    rotateError.set(ex);
                }
            });
            Thread terminator = new Thread(() -> rig.sessions().endSession(sessionId));
            rotator.start();
            terminator.start();
            rotator.join();
            terminator.join();

            if (rotated.get() != null) {
                // 旋转先完成：结束操作随后吊销整族，新凭证必须已失效。
                expectTokenReject(RejectionReason.REVOKED,
                        () -> rig.tokens().validateAccess(rotated.get().accessToken().getId()));
                if (round == 0) {
                    log.info("[结束竞态] 旋转先成功，但新 access 已随会话结束失效 reason=REVOKED");
                }
            } else {
                // 结束先生效：旋转必须被拒绝，不能返回可用新凭证。
                assertEquals(RejectionReason.REVOKED, rotateError.get().getReason());
                if (round == 0) {
                    log.info("[结束竞态] 会话先结束，旋转被拒绝 reason={}",
                            rotateError.get().getReason());
                }
            }
            assertTrue(rig.sessions().listSessions("judy").isEmpty(),
                    "会话结束后清单必须为空（第 " + round + " 轮）");
        }
        log.info("[结束竞态] 100 轮并发结束，未出现会话结束后仍可用的新凭证");
    }

    @Test
    void session_limit_is_enforced_and_releases_after_end_or_expiry() {
        Rig rig = rig(2);
        rig.tokens().issue("kate", "phone");
        rig.tokens().issue("kate", "tablet");
        log.info("[上限] kate 已建立 2 个会话（上限=2）");

        // 到上限：明确拒绝，而不是挤掉旧会话。
        SessionException ex = assertThrows(SessionException.class,
                () -> rig.tokens().issue("kate", "pc"));
        assertEquals(SessionRejection.SESSION_LIMIT_EXCEEDED, ex.getReason());
        log.info("[上限] 第 3 个会话被拒绝 reason={} msg={}", ex.getReason(), ex.getMessage());
        assertEquals(2, rig.sessions().listSessions("kate").size(), "旧会话不得被挤掉");

        // 结束一个后可以再签发。
        String sessionId = rig.sessions().listSessions("kate").get(0).sessionId();
        rig.sessions().endSession(sessionId);
        rig.tokens().issue("kate", "pc");
        assertEquals(2, rig.sessions().listSessions("kate").size());
        log.info("[上限] 结束一个会话后可再次签发");

        // 会话自然到期后不占名额。
        rig.clock().setMillis(T0 + REFRESH_TTL + 1L);
        rig.tokens().issue("kate", "watch");
        rig.tokens().issue("kate", "tv");
        assertEquals(2, rig.sessions().listSessions("kate").stream()
                .filter(v -> !v.expired()).count(), "到期会话不应占用上限名额");
        log.info("[上限] 旧会话到期后释放名额，新会话签发成功");
    }

    /**
     * 可插闩的注册表：把“会话已登记、凭证尚未登记进家族”的窗口固定下来，
     * 让结束操作确定性地落进这个窗口，复现签发与结束的竞态。
     */
    private static final class LatchingRegistry extends SessionRegistry {
        private final CountDownLatch sessionRegistered = new CountDownLatch(1);
        private final CountDownLatch proceedRegister = new CountDownLatch(1);
        private final CountDownLatch sessionEnded = new CountDownLatch(1);
        private volatile String createdSessionId;

        LatchingRegistry(int maxActivePerSubject, Clock clock) {
            super(maxActivePerSubject, clock);
        }

        @Override
        public LoginSession create(String subject, String deviceLabel, String sessionId,
                                   long createdAt, long refreshExpiresAt) {
            LoginSession session =
                    super.create(subject, deviceLabel, sessionId, createdAt, refreshExpiresAt);
            createdSessionId = sessionId;
            sessionRegistered.countDown();
            awaitQuietly(proceedRegister);
            return session;
        }

        @Override
        public boolean markEnded(String sessionId) {
            boolean result = super.markEnded(sessionId);
            if (result) {
                sessionEnded.countDown();
            }
            return result;
        }

        private static void awaitQuietly(CountDownLatch latch) {
            try {
                if (!latch.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("等待闩超时");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }
    }

    private record LatchedRig(MutableClock clock, LatchingRegistry registry,
                              TokenService tokens, SessionService sessions) {
    }

    private LatchedRig latchedRig() {
        MutableClock clock = new MutableClock(T0);
        LatchingRegistry registry = new LatchingRegistry(5, clock);
        TokenService tokens = new TokenService(ACCESS_TTL, REFRESH_TTL, SKEW,
                REPLAY_GRACE, registry, clock);
        return new LatchedRig(clock, registry, tokens, new SessionService(registry, tokens));
    }

    /** 启动一个签发线程，并把结束操作确定性地插进“会话已登记、凭证未登记”的窗口。 */
    private void runIssueVsEnd(LatchedRig rig, Runnable endAction, String tag) throws Exception {
        AtomicReference<TokenPair> issued = new AtomicReference<>();
        AtomicReference<TokenException> issueError = new AtomicReference<>();
        Thread issuer = new Thread(() -> {
            try {
                issued.set(rig.tokens().issue("amy", "phone"));
            } catch (TokenException ex) {
                issueError.set(ex);
            }
        });
        issuer.start();
        assertTrue(rig.registry().sessionRegistered.await(5, TimeUnit.SECONDS),
                "会话应已登记进注册表（" + tag + "）");

        Thread ender = new Thread(endAction);
        ender.start();
        assertTrue(rig.registry().sessionEnded.await(5, TimeUnit.SECONDS),
                "结束操作应已生效（会话状态跃迁）（" + tag + "）");
        // 放行签发线程：把凭证登记进一个“已被结束”的会话名下。
        rig.registry().proceedRegister.countDown();
        issuer.join(5_000L);
        ender.join(5_000L);

        assertTrue(rig.sessions().listSessions("amy").isEmpty(),
                "会话结束后清单必须为空（" + tag + "）");
        if (issued.get() != null) {
            // 签发返回了凭证：会话既已结束，下一次使用必须被拒。
            expectTokenReject(RejectionReason.REVOKED,
                    () -> rig.tokens().validateAccess(issued.get().accessToken().getId()));
            expectTokenReject(RejectionReason.REVOKED,
                    () -> rig.tokens().rotate(issued.get().refreshToken().getId()));
            log.info("[{}] 签发先完成，但结束已生效：刚签发的 access/refresh 均被拒 reason=REVOKED", tag);
        } else {
            // 结束先生效：签发必须被拒绝，不能返回可用凭证。
            assertEquals(RejectionReason.REVOKED, issueError.get().getReason(),
                    "签发应被拒绝且原因可区分（" + tag + "）");
            log.info("[{}] 结束先生效，签发被拒绝 reason={}", tag, issueError.get().getReason());
        }
    }

    @Test
    void end_all_racing_issue_never_leaves_usable_tokens() throws Exception {
        LatchedRig rig = latchedRig();
        AtomicInteger ended = new AtomicInteger();
        runIssueVsEnd(rig, () -> ended.set(rig.sessions().endAllSessions("amy")), "签发竞态-全部下线");
        assertEquals(1, ended.get(), "整体下线必须如实生效：结束会话数=1");
        log.info("[签发竞态-全部下线] 结束操作返回 ended=1，不存在“看似成功实际未生效”");
    }

    @Test
    void end_single_session_racing_issue_never_leaves_usable_tokens() throws Exception {
        LatchedRig rig = latchedRig();
        runIssueVsEnd(rig,
                () -> rig.sessions().endSession(rig.registry().createdSessionId),
                "签发竞态-单会话下线");
    }

    @Test
    void issue_and_end_all_stress_invariant() throws Exception {
        for (int round = 0; round < 100; round++) {
            Rig rig = rig(5);
            AtomicReference<TokenPair> issued = new AtomicReference<>();
            AtomicReference<TokenException> issueError = new AtomicReference<>();
            Thread issuer = new Thread(() -> {
                try {
                    issued.set(rig.tokens().issue("sam", "phone"));
                } catch (TokenException ex) {
                    issueError.set(ex);
                }
            });
            Thread ender = new Thread(() -> rig.sessions().endAllSessions("sam"));
            issuer.start();
            ender.start();
            issuer.join();
            ender.join();

            if (issued.get() != null) {
                String sessionId = issued.get().accessToken().getFamilyId();
                boolean stillActive = rig.sessions().listSessions("sam").stream()
                        .anyMatch(v -> v.sessionId().equals(sessionId));
                if (!stillActive) {
                    // 会话已被结束：它名下的凭证下一次使用必须被拒。
                    expectTokenReject(RejectionReason.REVOKED,
                            () -> rig.tokens().validateAccess(issued.get().accessToken().getId()));
                }
            }
        }
        log.info("[签发竞态-压测] 100 轮并发签发/全部下线，未出现已结束会话仍可用凭证");
    }
}

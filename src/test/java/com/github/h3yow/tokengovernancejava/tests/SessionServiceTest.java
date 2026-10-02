package com.github.h3yow.tokengovernancejava.tests;

import com.github.h3yow.tokengovernancejava.session.SessionException;
import com.github.h3yow.tokengovernancejava.session.SessionInfo;
import com.github.h3yow.tokengovernancejava.session.SessionRejectionReason;
import com.github.h3yow.tokengovernancejava.token.AccessValidation;
import com.github.h3yow.tokengovernancejava.token.RejectionReason;
import com.github.h3yow.tokengovernancejava.token.TokenException;
import com.github.h3yow.tokengovernancejava.token.TokenPair;
import com.github.h3yow.tokengovernancejava.token.TokenService;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 按登录会话（设备）管理的测试：多会话并存、清单、单独/全部下线、重放作废、
 * 结束与刷新并发竞态、会话数量上限。每个用例都打印输入与判定依据。
 */
class SessionServiceTest {

    private static final Logger log = LoggerFactory.getLogger(SessionServiceTest.class);

    private static final long ACCESS_TTL = 60_000L;
    private static final long REFRESH_TTL = 300_000L;
    private static final long SKEW = 30_000L;
    /** 需大于 TokenService 内部“并发首用竞争”宽限窗口(500ms)，以便稳定构造事后重放。 */
    private static final long REPLAY_SETTLE_MILLIS = 700L;

    private TokenService newService(MutableClock clock, int maxSessions) {
        return new TokenService(ACCESS_TTL, REFRESH_TTL, SKEW, maxSessions, clock);
    }

    private void expectReject(RejectionReason reason, Runnable action) {
        TokenException ex = assertThrows(TokenException.class, action::run);
        assertEquals(reason, ex.getReason(),
                "拒绝原因应为 " + reason + "，实际 " + ex.getReason());
    }

    private void assertAccessRejected(TokenService svc, String accessId, RejectionReason reason) {
        TokenException ex = assertThrows(TokenException.class,
                () -> svc.validateAccess(accessId));
        assertEquals(reason, ex.getReason());
    }

    @Test
    void multiple_sessions_coexist_and_list_exposes_only_metadata() {
        MutableClock clock = new MutableClock(1_000_000L);
        TokenService svc = newService(clock, 5);

        TokenPair phone = svc.issue("alice", "phone");
        TokenPair tablet = svc.issue("alice", "tablet");
        TokenPair laptop = svc.issue("alice", "laptop");
        String s1 = phone.accessToken().getFamilyId();
        String s2 = tablet.accessToken().getFamilyId();
        String s3 = laptop.accessToken().getFamilyId();
        log.info("[多会话] alice 三设备签发 session={}/phone {}/tablet {}/laptop", s1, s2, s3);

        // 三个会话互不影响：各自的访问凭证此刻都有效。
        assertEquals("alice", svc.validateAccess(phone.accessToken().getId()).subject());
        assertEquals("alice", svc.validateAccess(tablet.accessToken().getId()).subject());
        assertEquals("alice", svc.validateAccess(laptop.accessToken().getId()).subject());

        List<SessionInfo> sessions = svc.listSessions("alice");
        log.info("[会话清单] count={} 明细={}", sessions.size(), sessions);
        assertEquals(3, sessions.size());
        assertEquals(List.of("phone", "tablet", "laptop"),
                sessions.stream().map(SessionInfo::deviceLabel).toList());
        // 清单只暴露标识与元信息；SessionInfo 中根本不存在凭证字段（编译期保证）。
        for (SessionInfo info : sessions) {
            assertNotNull(info.sessionId());
            assertEquals("alice", info.subject());
            assertTrue(info.createdAt() > 0 && info.expiresAt() > info.createdAt());
            assertEquals(info.createdAt(), info.lastRefreshedAt());
        }
    }

    @Test
    void legacy_issue_without_device_is_default_session() {
        MutableClock clock = new MutableClock(1_000_000L);
        TokenService svc = newService(clock, 5);
        // 老调用方式：issue(subject) 与 deviceLabel 传 null 都应归一成默认会话。
        TokenPair legacy = svc.issue("bob");
        TokenPair blankLabel = svc.issue("bob", null);
        log.info("[兼容] 老调用签发 session1={} session2={}",
                legacy.accessToken().getFamilyId(), blankLabel.accessToken().getFamilyId());

        List<SessionInfo> sessions = svc.listSessions("bob");
        assertEquals(2, sessions.size());
        assertEquals(List.of("default", "default"),
                sessions.stream().map(SessionInfo::deviceLabel).toList());
        assertEquals("bob", svc.validateAccess(legacy.accessToken().getId()).subject());
    }

    @Test
    void ending_one_session_does_not_affect_others() {
        MutableClock clock = new MutableClock(1_000_000L);
        TokenService svc = newService(clock, 5);
        TokenPair phone = svc.issue("alice", "phone");
        TokenPair tablet = svc.issue("alice", "tablet");
        String phoneSession = phone.accessToken().getFamilyId();

        // phone 先旋转一次，得到一对更新的凭证。
        TokenPair phoneRotated = svc.rotate(phone.refreshToken().getId());
        log.info("[单设备下线] phone session={} 旋转后新access={}",
                phoneSession, phoneRotated.accessToken().getId());

        svc.endSession(phoneSession);
        log.info("[单设备下线] 已结束 phone session={}", phoneSession);

        // phone 名下：最初的 access、旋转刚换出的 access、两个 refresh 全部立即失效。
        assertAccessRejected(svc, phone.accessToken().getId(), RejectionReason.REVOKED);
        assertAccessRejected(svc, phoneRotated.accessToken().getId(), RejectionReason.REVOKED);
        expectReject(RejectionReason.REVOKED,
                () -> svc.rotate(phoneRotated.refreshToken().getId()));

        // tablet 完全不受影响。
        AccessValidation tabletOk = svc.validateAccess(tablet.accessToken().getId());
        assertEquals("alice", tabletOk.subject());
        TokenPair tabletRotated = svc.rotate(tablet.refreshToken().getId());
        assertEquals("alice", svc.validateAccess(tabletRotated.accessToken().getId()).subject());
        log.info("[单设备下线] tablet 仍可用，新access={}", tabletRotated.accessToken().getId());

        // 清单只剩 tablet。
        List<SessionInfo> remaining = svc.listSessions("alice");
        assertEquals(1, remaining.size());
        assertEquals("tablet", remaining.get(0).deviceLabel());

        // 重复结束 / 结束不存在会话都要如实报错。
        SessionException again = assertThrows(SessionException.class,
                () -> svc.endSession(phoneSession));
        assertEquals(SessionRejectionReason.SESSION_NOT_FOUND, again.getReason());
        SessionException ghost = assertThrows(SessionException.class,
                () -> svc.endSession("no-such-session"));
        assertEquals(SessionRejectionReason.SESSION_NOT_FOUND, ghost.getReason());
        log.info("[单设备下线] 重复/不存在会话结束均报 SESSION_NOT_FOUND");
    }

    @Test
    void ending_all_sessions_for_subject_only_affects_that_subject() {
        MutableClock clock = new MutableClock(1_000_000L);
        TokenService svc = newService(clock, 5);
        TokenPair a1 = svc.issue("alice", "phone");
        TokenPair a2 = svc.issue("alice", "tv");
        TokenPair b1 = svc.issue("bob", "phone");

        int ended = svc.endAllSessions("alice");
        log.info("[全部下线] alice 结束会话数={}", ended);
        assertEquals(2, ended);

        assertAccessRejected(svc, a1.accessToken().getId(), RejectionReason.REVOKED);
        assertAccessRejected(svc, a2.accessToken().getId(), RejectionReason.REVOKED);
        // bob 不受影响。
        assertEquals("bob", svc.validateAccess(b1.accessToken().getId()).subject());
        assertEquals(0, svc.listSessions("alice").size());
        assertEquals(1, svc.listSessions("bob").size());
        // 无有效会话时再次结束全部：返回 0，不报错。
        assertEquals(0, svc.endAllSessions("alice"));
    }

    @Test
    void replay_revokes_whole_session_including_just_rotated_access() throws Exception {
        MutableClock clock = new MutableClock(1_000_000L);
        TokenService svc = newService(clock, 5);
        TokenPair first = svc.issue("carol", "phone");
        String stolenRefresh = first.refreshToken().getId();

        TokenPair rotated = svc.rotate(stolenRefresh);
        String freshAccess = rotated.accessToken().getId();
        log.info("[重放作废] 首次旋转成功 旧refresh={} 看似很新的access={} 新refresh={}",
                stolenRefresh, freshAccess, rotated.refreshToken().getId());

        // 待旋转收尾、越过“并发首用竞争”宽限窗口后，攻击者再拿旧 refresh 重放。
        Thread.sleep(REPLAY_SETTLE_MILLIS);
        TokenException ex = assertThrows(TokenException.class,
                () -> svc.rotate(stolenRefresh));
        log.info("[重放作废] 旧 refresh 再次出现 => reason={} msg={}",
                ex.getReason(), ex.getMessage());
        assertEquals(RejectionReason.REPLAY_DETECTED, ex.getReason());

        // 整个会话作废：刚换出的新 access 立即失效，新 refresh 也被连带吊销。
        assertAccessRejected(svc, freshAccess, RejectionReason.REVOKED);
        assertAccessRejected(svc, first.accessToken().getId(), RejectionReason.REVOKED);
        expectReject(RejectionReason.REVOKED,
                () -> svc.rotate(rotated.refreshToken().getId()));
        assertEquals(0, svc.listSessions("carol").size());

        // 重放原因与其它情形可区分：不是 NOT_FOUND / EXPIRED / WRONG_TYPE / ALREADY_CONSUMED。
        assertFalse(ex.getReason() == RejectionReason.NOT_FOUND);
        assertFalse(ex.getReason() == RejectionReason.EXPIRED);
        assertFalse(ex.getReason() == RejectionReason.WRONG_TYPE);
        log.info("[重放作废] 会话清单为空，REPLAY_DETECTED 与其它拒绝原因可区分");
    }

    @Test
    void concurrent_refresh_replay_attempt_still_only_one_valid_pair() throws Exception {
        MutableClock clock = new MutableClock(1_000_000L);
        TokenService svc = newService(clock, 5);
        TokenPair pair = svc.issue("dave", "phone");
        String refreshId = pair.refreshToken().getId();
        int threads = 24;
        log.info("[并发重放] refresh={} 并发线程数={}", refreshId, threads);

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger consumed = new AtomicInteger();
        AtomicReference<TokenPair> winner = new AtomicReference<>();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    TokenPair next = svc.rotate(refreshId);
                    success.incrementAndGet();
                    winner.compareAndSet(null, next);
                } catch (TokenException ex) {
                    if (ex.getReason() == RejectionReason.ALREADY_CONSUMED) {
                        consumed.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS));
        pool.shutdown();
        log.info("[并发重放] 成功={} 并发抢输(ALREADY_CONSUMED)={}",
                success.get(), consumed.get());

        assertEquals(1, success.get(), "同一张刷新凭证并发下最多成功一次");
        assertEquals(threads - 1, consumed.get(), "其余并发请求应全部按 ALREADY_CONSUMED 拒绝");
        // 赢家那对凭证有效；不会出现两份都有效的凭证。
        assertNotNull(winner.get());
        assertEquals("dave", svc.validateAccess(winner.get().accessToken().getId()).subject());
        assertEquals(1, svc.listSessions("dave").size(), "并发抢输不应作废会话");
    }

    @Test
    void end_session_racing_with_refresh_never_returns_usable_pair() throws Exception {
        // 反复制造“结束会话与刷新并发”，二者任一顺序都不允许留下可用新凭证。
        for (int round = 0; round < 100; round++) {
            MutableClock clock = new MutableClock(1_000_000L + round);
            TokenService svc = newService(clock, 5);
            TokenPair pair = svc.issue("erin", "phone");
            String refresh = pair.refreshToken().getId();
            String sessionId = pair.accessToken().getFamilyId();
            AtomicReference<TokenPair> winner = new AtomicReference<>();
            AtomicReference<TokenException> rotateError = new AtomicReference<>();

            Thread rotator = new Thread(() -> {
                try {
                    winner.set(svc.rotate(refresh));
                } catch (TokenException ex) {
                    rotateError.set(ex);
                }
            });
            Thread ender = new Thread(() -> svc.endSession(sessionId));
            rotator.start();
            ender.start();
            rotator.join();
            ender.join();

            if (winner.get() != null) {
                // 刷新先赢：会话结束的整族吊销必须覆盖刚换出的新凭证。
                TokenException e = assertThrows(TokenException.class,
                        () -> svc.validateAccess(winner.get().accessToken().getId()));
                assertEquals(RejectionReason.REVOKED, e.getReason(),
                        "会话结束必须让旋转刚换出的 access 立即失效");
            } else {
                // 结束先生效：刷新必须被明确拒绝，且不能是“成功”。
                assertNotNull(rotateError.get());
                assertTrue(rotateError.get().getReason() == RejectionReason.REVOKED
                                || rotateError.get().getReason() == RejectionReason.NOT_FOUND,
                        "结束先生效时刷新应被拒绝，实际=" + rotateError.get().getReason());
            }
            // 无论谁先谁后，会话最终都应已结束。
            assertEquals(0, svc.listSessions("erin").size());
        }
        log.info("[结束/刷新竞态] 100 轮结束：未出现会话已结束却返回可用新凭证，结束均已生效");
    }

    @Test
    void session_limit_is_enforced_without_evicting_old_sessions() {
        MutableClock clock = new MutableClock(1_000_000L);
        int limit = 3;
        TokenService svc = newService(clock, limit);
        svc.issue("frank", "phone");
        svc.issue("frank", "tablet");
        svc.issue("frank", "laptop");
        log.info("[会话上限] 已签发 {} 个会话，达到上限", limit);

        SessionException ex = assertThrows(SessionException.class,
                () -> svc.issue("frank", "watch"));
        assertEquals(SessionRejectionReason.SESSION_LIMIT_REACHED, ex.getReason());
        log.info("[会话上限] 第 4 台设备被拒 reason={} msg={}", ex.getReason(), ex.getMessage());

        // 不悄悄挤掉旧会话：仍然是原来 3 个，且最旧的 phone 依旧有效。
        List<SessionInfo> sessions = svc.listSessions("frank");
        assertEquals(limit, sessions.size());
        assertEquals(List.of("phone", "tablet", "laptop"),
                sessions.stream().map(SessionInfo::deviceLabel).toList());

        // 结束一个会话腾出名额后，新设备才能签发。
        svc.endSession(sessions.get(0).sessionId());
        TokenPair watch = svc.issue("frank", "watch");
        assertNotNull(watch);
        assertEquals(limit, svc.listSessions("frank").size());
        log.info("[会话上限] 结束旧会话后 watch 签发成功 session={}",
                watch.accessToken().getFamilyId());
    }

    @Test
    void expired_session_stops_counting_toward_limit_and_disappears_from_list() {
        long t0 = 1_000_000L;
        MutableClock clock = new MutableClock(t0);
        TokenService svc = newService(clock, 2);
        svc.issue("grace", "phone");
        svc.issue("grace", "tablet");
        // 刷新凭证自然到期（含 skew 容忍边界之后）。
        clock.setMillis(t0 + REFRESH_TTL + SKEW + 1L);
        List<SessionInfo> alive = svc.listSessions("grace");
        log.info("[到期] 全部到期后清单有效会话数={}", alive.size());
        assertEquals(0, alive.size());
        // 到期会话不再占用名额，可签发新会话而不触发上限。
        TokenPair laptop = svc.issue("grace", "laptop");
        assertNotNull(laptop);
        assertEquals(1, svc.listSessions("grace").size());
    }
}

package com.github.h3yow.tokengovernancejava.tests;

import com.github.h3yow.tokengovernancejava.token.AccessValidation;
import com.github.h3yow.tokengovernancejava.token.RejectionReason;
import com.github.h3yow.tokengovernancejava.token.TokenException;
import com.github.h3yow.tokengovernancejava.token.TokenPair;
import com.github.h3yow.tokengovernancejava.token.TokenService;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 凭证生命周期测试：并发旋转、重放、吊销、过期与时钟偏差。
 * 每个用例都打印输入与判定/拒绝依据。
 */
class TokenServiceTest {

    private static final Logger log = LoggerFactory.getLogger(TokenServiceTest.class);

    private static final long ACCESS_TTL = 60_000L;
    private static final long REFRESH_TTL = 300_000L;
    private static final long SKEW = 30_000L;

    private TokenService serviceAt(long epochMillis, MutableClock clock) {
        return new TokenService(ACCESS_TTL, REFRESH_TTL, SKEW, clock);
    }

    private void expectReject(RejectionReason reason, Runnable action) {
        TokenException ex = assertThrows(TokenException.class, action::run);
        assertEquals(reason, ex.getReason(),
                "拒绝原因应为 " + reason + "，实际 " + ex.getReason());
    }

    @Test
    void issue_and_validate_access_token() {
        MutableClock clock = new MutableClock(1_000_000L);
        TokenService svc = serviceAt(0, clock);
        TokenPair pair = svc.issue("alice");
        log.info("[签发] subject=alice access={} refresh={}",
                pair.accessToken().getId(), pair.refreshToken().getId());

        AccessValidation v = svc.validateAccess(pair.accessToken().getId());
        log.info("[校验] access={} => subject={} 通过", pair.accessToken().getId(), v.subject());
        assertEquals("alice", v.subject());
    }

    @Test
    void concurrent_refresh_only_one_succeeds() throws Exception {
        MutableClock clock = new MutableClock(1_000_000L);
        TokenService svc = serviceAt(0, clock);
        TokenPair pair = svc.issue("bob");
        String refreshId = pair.refreshToken().getId();
        int threads = 16;
        log.info("[并发刷新] refresh={} 并发线程数={}", refreshId, threads);

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        AtomicReference<RejectionReason> firstRejectReason = new AtomicReference<>();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    TokenPair next = svc.rotate(refreshId);
                    success.incrementAndGet();
                    log.info("[并发刷新] 线程成功，新 access={} 新 refresh={}",
                            next.accessToken().getId(), next.refreshToken().getId());
                } catch (TokenException ex) {
                    rejected.incrementAndGet();
                    firstRejectReason.compareAndSet(null, ex.getReason());
                    log.info("[并发刷新] 线程被拒绝 reason={} msg={}", ex.getReason(), ex.getMessage());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS), "并发任务应在超时前结束");
        pool.shutdown();

        log.info("[并发刷新] 结果 成功={} 拒绝={} 首个拒绝原因={}",
                success.get(), rejected.get(), firstRejectReason.get());
        assertEquals(1, success.get(), "同一刷新凭证并发旋转必须恰好一次成功");
        assertEquals(threads - 1, rejected.get(), "其余请求必须被明确拒绝");
        assertEquals(RejectionReason.ALREADY_CONSUMED, firstRejectReason.get(),
                "并发失败者原因应为 ALREADY_CONSUMED");
    }

    @Test
    void replayed_refresh_token_after_rotation_revokes_session_as_replay() throws Exception {
        MutableClock clock = new MutableClock(1_000_000L);
        TokenService svc = serviceAt(0, clock);
        TokenPair first = svc.issue("carol");
        String oldRefresh = first.refreshToken().getId();

        TokenPair second = svc.rotate(oldRefresh);
        assertNotNull(second);
        log.info("[重放] 首次旋转成功 旧refresh={} 新refresh={} 新access={}",
                oldRefresh, second.refreshToken().getId(), second.accessToken().getId());

        // 越过“并发首用竞争”宽限窗口后再次出现同一张已消费刷新凭证 => 事后重放，
        // 区别于并发抢输：判 REPLAY_DETECTED 并作废整个会话。
        Thread.sleep(700L);
        TokenException ex = assertThrows(TokenException.class, () -> svc.rotate(oldRefresh));
        assertEquals(RejectionReason.REPLAY_DETECTED, ex.getReason());
        log.info("[重放] 再次使用旧 refresh={} 被拒绝 reason={} msg={}",
                oldRefresh, ex.getReason(), ex.getMessage());

        // 连第一次旋转换出的新 access 也立即失效。
        TokenException accessEx = assertThrows(TokenException.class,
                () -> svc.validateAccess(second.accessToken().getId()));
        assertEquals(RejectionReason.REVOKED, accessEx.getReason());
        log.info("[重放] 旋转新 access 已随会话作废 reason={}", accessEx.getReason());
    }

    @Test
    void unknown_token_is_rejected_as_not_found() {
        MutableClock clock = new MutableClock(1_000_000L);
        TokenService svc = serviceAt(0, clock);
        TokenException ex = assertThrows(TokenException.class, () -> svc.rotate("does-not-exist"));
        assertEquals(RejectionReason.NOT_FOUND, ex.getReason());
        log.info("[不存在] rotate 未知凭证 reason={} msg={}", ex.getReason(), ex.getMessage());

        TokenException ex2 = assertThrows(TokenException.class, () -> svc.validateAccess("nope"));
        assertEquals(RejectionReason.NOT_FOUND, ex2.getReason());
        log.info("[不存在] validate 未知凭证 reason={} msg={}", ex2.getReason(), ex2.getMessage());
    }

    @Test
    void expired_refresh_is_rejected_as_expired() {
        long t0 = 1_000_000L;
        MutableClock clock = new MutableClock(t0);
        TokenService svc = serviceAt(0, clock);
        TokenPair p = svc.issue("dave");
        // 前进到“超出 skew 容忍窗口之后”，此时确实过期。
        long later = t0 + REFRESH_TTL + SKEW + 1L;
        clock.setMillis(later);
        TokenException ex = assertThrows(TokenException.class,
                () -> svc.rotate(p.refreshToken().getId()));
        assertEquals(RejectionReason.EXPIRED, ex.getReason());
        log.info("[过期] 当前时间={} refresh到期={} skew={} reason={} msg={}",
                later, p.refreshToken().getExpiresAt(), SKEW, ex.getReason(), ex.getMessage());
    }

    @Test
    void token_within_clock_skew_is_not_misjudged_expired() {
        long t0 = 1_000_000L;
        MutableClock clock = new MutableClock(t0);
        TokenService svc = serviceAt(0, clock);
        TokenPair pair = svc.issue("erin");
        // 已越过名义过期点，但仍在 skew 容忍窗口内：访问凭证必须仍判有效。
        clock.setMillis(t0 + ACCESS_TTL + SKEW - 1L);
        AccessValidation v = svc.validateAccess(pair.accessToken().getId());
        log.info("[时钟偏差] 名义已过期但在偏差窗口内 access到期={} 当前={} skew={} => subject={}",
                pair.accessToken().getExpiresAt(), clock.millis(), SKEW, v.subject());
        assertEquals("erin", v.subject());

        // 刚好越过容忍窗口边界才判过期。
        clock.setMillis(t0 + ACCESS_TTL + SKEW);
        TokenException ex = assertThrows(TokenException.class,
                () -> svc.validateAccess(pair.accessToken().getId()));
        assertEquals(RejectionReason.EXPIRED, ex.getReason());
        log.info("[时钟偏差] 越过容忍边界 当前={} reason={}", clock.millis(), ex.getReason());
    }

    @Test
    void revoked_refresh_and_family_are_rejected() {
        MutableClock clock = new MutableClock(1_000_000L);
        TokenService svc = serviceAt(0, clock);
        TokenPair pair = svc.issue("frank");
        String refresh = pair.refreshToken().getId();
        svc.revokeRefresh(refresh);
        log.info("[吊销] 已吊销 refresh={}（整族）", refresh);

        TokenException ex = assertThrows(TokenException.class, () -> svc.rotate(refresh));
        assertEquals(RejectionReason.REVOKED, ex.getReason());
        log.info("[吊销] 再用 refresh reason={} msg={}", ex.getReason(), ex.getMessage());

        TokenException ex2 = assertThrows(TokenException.class,
                () -> svc.validateAccess(pair.accessToken().getId()));
        assertEquals(RejectionReason.REVOKED, ex2.getReason());
        log.info("[吊销] 同族 access 校验 reason={}", ex2.getReason());
    }

    @Test
    void revocation_beats_in_flight_rotation() throws Exception {
        // 反复制造“旋转与吊销并发”，验证吊销之后不存在仍可用的新凭证。
        for (int round = 0; round < 100; round++) {
            MutableClock clock = new MutableClock(1_000_000L + round);
            TokenService svc = serviceAt(0, clock);
            TokenPair pair = svc.issue("grace");
            String refresh = pair.refreshToken().getId();
            AtomicReference<TokenPair> winner = new AtomicReference<>();
            AtomicReference<TokenException> rotateError = new AtomicReference<>();

            Thread rotator = new Thread(() -> {
                try {
                    winner.set(svc.rotate(refresh));
                } catch (TokenException ex) {
                    rotateError.set(ex);
                }
            });
            Thread revoker = new Thread(() -> svc.revokeRefresh(refresh));
            rotator.start();
            revoker.start();
            rotator.join();
            revoker.join();

            if (winner.get() != null) {
                // 旋转先赢：其新家族与旧家族同 id，吊销整族已把新成员一并置 REVOKED。
                TokenException e = assertThrows(TokenException.class,
                        () -> svc.validateAccess(winner.get().accessToken().getId()));
                assertEquals(RejectionReason.REVOKED, e.getReason(),
                        "吊销整族必须覆盖旋转刚产生的新凭证");
                if (round == 0) {
                    log.info("[吊销竞态] 旋转先成功，但新 access 已随整族吊销 reason={}",
                            e.getReason());
                }
            } else {
                assertEquals(RejectionReason.REVOKED, rotateError.get().getReason());
                if (round == 0) {
                    log.info("[吊销竞态] 吊销先生效，旋转被拒绝 reason={}",
                            rotateError.get().getReason());
                }
            }
        }
        log.info("[吊销竞态] 100 轮并发结束，未出现吊销后仍有效的新凭证");
    }
}

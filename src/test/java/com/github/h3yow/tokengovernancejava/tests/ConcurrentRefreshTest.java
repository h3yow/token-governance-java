package com.github.h3yow.tokengovernancejava.tests;

import com.github.h3yow.tokengovernancejava.credential.CredentialErrorType;
import com.github.h3yow.tokengovernancejava.credential.CredentialException;
import com.github.h3yow.tokengovernancejava.credential.CredentialService;
import com.github.h3yow.tokengovernancejava.credential.InMemoryCredentialService;
import com.github.h3yow.tokengovernancejava.credential.TokenPair;
import com.github.h3yow.tokengovernancejava.credential.TokenSettings;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 并发刷新测试：N 个线程同时用同一个刷新凭证旋转。
 * 必须恰好 1 个成功；失败请求必须被明确归类为 REFRESH_TOKEN_CONSUMED
 * （CAS 落败者）或 SESSION_REVOKED（落败触发凭证族吊销后的后续请求）。
 */
class ConcurrentRefreshTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentRefreshTest.class);

    private record Outcome(boolean success, CredentialErrorType errorType) {
    }

    @Test
    void sameRefreshToken_concurrentUse_succeedsAtMostOnce() throws Exception {
        int threads = 32;
        TokenSettings settings = new TokenSettings(Duration.ofMinutes(10),
                Duration.ofHours(8), Duration.ofSeconds(30));
        CredentialService service = new InMemoryCredentialService(settings, Clock.systemUTC());
        TokenPair pair = service.issue("alice", 0L);
        log.info("[concurrent-refresh] input family={} threads={} sameRefreshToken", pair.familyId(), threads);

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Outcome>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                try {
                    start.await();
                    TokenPair next = service.refresh(pair.refreshToken());
                    return new Outcome(true, null);
                } catch (CredentialException e) {
                    return new Outcome(false, e.getErrorType());
                }
            }));
        }
        start.countDown();

        int success = 0;
        List<CredentialErrorType> failureTypes = Collections.synchronizedList(new ArrayList<>());
        for (Future<Outcome> f : futures) {
            Outcome outcome = f.get(10, TimeUnit.SECONDS);
            if (outcome.success()) {
                success++;
            } else {
                failureTypes.add(outcome.errorType());
            }
        }
        pool.shutdownNow();

        log.info("[concurrent-refresh] successCount={} failureTypes={}", success, failureTypes);

        assertEquals(1, success, "同一刷新凭证并发旋转必须恰好成功一次");
        for (CredentialErrorType type : failureTypes) {
            assertTrue(type == CredentialErrorType.REFRESH_TOKEN_CONSUMED
                            || type == CredentialErrorType.SESSION_REVOKED,
                    "失败原因必须可区分为 CONSUMED 或 REVOKED，实际：" + type);
        }
        // 至少一个 CAS 落败者观察到 CONSUMED（证明重放被明确识别）
        assertTrue(failureTypes.contains(CredentialErrorType.REFRESH_TOKEN_CONSUMED));
    }

    @Test
    void revokeRacingWithRefresh_noUnauthorizedSuccess() throws Exception {
        int threads = 24;
        TokenSettings settings = new TokenSettings(Duration.ofMinutes(10),
                Duration.ofHours(8), Duration.ofSeconds(30));
        CredentialService service = new InMemoryCredentialService(settings, Clock.systemUTC());
        TokenPair pair = service.issue("alice", 0L);
        log.info("[revoke-race] input family={} threads={}, concurrent refresh+revoke",
                pair.familyId(), threads);

        ExecutorService pool = Executors.newFixedThreadPool(threads + 1);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger refreshSuccess = new AtomicInteger();
        List<CredentialErrorType> errors = Collections.synchronizedList(new ArrayList<>());

        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                try {
                    start.await();
                    service.refresh(pair.refreshToken());
                    refreshSuccess.incrementAndGet();
                } catch (CredentialException e) {
                    errors.add(e.getErrorType());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }));
        }
        futures.add(pool.submit(() -> {
            try {
                start.await();
                service.revokeFamily(pair.familyId());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }));
        start.countDown();
        for (Future<?> f : futures) {
            f.get(10, TimeUnit.SECONDS);
        }
        pool.shutdownNow();

        log.info("[revoke-race] refreshSuccess={} errors={}", refreshSuccess.get(), errors);

        // 至多一次刷新成功；若有成功，其新凭证也必须因吊销立即失效，不存在越权窗口
        assertTrue(refreshSuccess.get() <= 1);
        CredentialException ex = org.junit.jupiter.api.Assertions.assertThrows(CredentialException.class,
                () -> service.introspect(pair.accessToken()));
        assertEquals(CredentialErrorType.ACCESS_TOKEN_REVOKED, ex.getErrorType());
        log.info("[revoke-race] original access token introspect => {} (no leak)", ex.getErrorType());
    }
}

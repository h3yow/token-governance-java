package com.github.h3yow.tokengovernancejava.tests;

import com.github.h3yow.tokengovernancejava.credential.CredentialException;
import com.github.h3yow.tokengovernancejava.credential.CredentialService;
import com.github.h3yow.tokengovernancejava.credential.InMemoryCredentialService;
import com.github.h3yow.tokengovernancejava.credential.TokenPair;
import com.github.h3yow.tokengovernancejava.credential.TokenSettings;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 凭证签发/刷新/吊销/时钟偏差相关单测。
 * 每个用例打印输入参数、期望与实际错误归类。
 */
class CredentialServiceTest {

    private static final Logger log = LoggerFactory.getLogger(CredentialServiceTest.class);

    /** 可手动拨动的时钟。 */
    static final class MutableClock extends Clock {
        private Instant instant;

        MutableClock(Instant start) {
            this.instant = start;
        }

        void advance(Duration d) {
            instant = instant.plus(d);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }

    private MutableClock clock;
    private CredentialService service;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-09-23T00:00:00Z"));
        TokenSettings settings = new TokenSettings(
                Duration.ofMinutes(10), Duration.ofHours(8), Duration.ofSeconds(30));
        service = new InMemoryCredentialService(settings, clock);
    }

    @Test
    void issueAndIntrospect_success() {
        TokenPair pair = service.issue("alice", 0L);
        log.info("[issue-and-introspect] input subject=alice version=0 => pair family={}", pair.familyId());

        var credential = service.introspect(pair.accessToken());
        assertEquals("alice", credential.subjectId());
        assertEquals(0L, credential.version());
        log.info("[issue-and-introspect] introspect subject={} version={} jti={}",
                credential.subjectId(), credential.version(), credential.jti());
    }

    @Test
    void refreshRotatesOnce_oldRefreshReplayIsRejectedAndClassified() {
        TokenPair pair = service.issue("alice", 0L);
        String first = pair.refreshToken();
        log.info("[refresh-replay] input firstRefresh={}", first);

        TokenPair rotated = service.refresh(first);
        assertNotEquals(first, rotated.refreshToken());
        log.info("[refresh-replay] first refresh succeeded, newRefresh={}", rotated.refreshToken());

        CredentialException ex = assertThrows(CredentialException.class, () -> service.refresh(first));
        log.info("[refresh-replay] reuse result errorType={} message={}", ex.getErrorType(), ex.getMessage());
        assertEquals(com.github.h3yow.tokengovernancejava.credential.CredentialErrorType.REFRESH_TOKEN_CONSUMED,
                ex.getErrorType());

        // 重放检测：凭证族已被吊销，新凭证同样不能再使用
        CredentialException after = assertThrows(CredentialException.class,
                () -> service.introspect(rotated.accessToken()));
        log.info("[refresh-replay] post-replay introspect errorType={}", after.getErrorType());
        assertEquals(com.github.h3yow.tokengovernancejava.credential.CredentialErrorType.ACCESS_TOKEN_REVOKED,
                after.getErrorType());
    }

    @Test
    void unknownRefreshToken_isClassifiedNotFound() {
        log.info("[refresh-unknown] input refreshToken=not-a-real-token");
        CredentialException ex = assertThrows(CredentialException.class,
                () -> service.refresh("not-a-real-token"));
        log.info("[refresh-unknown] result errorType={}", ex.getErrorType());
        assertEquals(com.github.h3yow.tokengovernancejava.credential.CredentialErrorType.REFRESH_TOKEN_NOT_FOUND,
                ex.getErrorType());
    }

    @Test
    void expiredRefreshToken_isClassifiedExpired() {
        TokenPair pair = service.issue("alice", 0L);
        clock.advance(Duration.ofHours(8));
        clock.advance(Duration.ofMinutes(1));
        log.info("[refresh-expired] now advanced past refresh expiry, input family={}", pair.familyId());

        CredentialException ex = assertThrows(CredentialException.class,
                () -> service.refresh(pair.refreshToken()));
        log.info("[refresh-expired] result errorType={} message={}", ex.getErrorType(), ex.getMessage());
        assertEquals(com.github.h3yow.tokengovernancejava.credential.CredentialErrorType.REFRESH_TOKEN_EXPIRED,
                ex.getErrorType());
    }

    @Test
    void revokedFamily_refreshIsClassifiedRevoked() {
        TokenPair pair = service.issue("alice", 0L);
        service.revokeFamily(pair.familyId());
        log.info("[refresh-revoked] family={} revoked, attempting refresh", pair.familyId());

        CredentialException ex = assertThrows(CredentialException.class,
                () -> service.refresh(pair.refreshToken()));
        log.info("[refresh-revoked] result errorType={}", ex.getErrorType());
        assertEquals(com.github.h3yow.tokengovernancejava.credential.CredentialErrorType.SESSION_REVOKED,
                ex.getErrorType());
    }

    @Test
    void revokeAllForSubject_killsEveryFamily() {
        TokenPair p1 = service.issue("bob", 0L);
        TokenPair p2 = service.issue("bob", 0L);
        service.revokeAllForSubject("bob");
        log.info("[revoke-all] revoked two families for bob");

        CredentialException e1 = assertThrows(CredentialException.class, () -> service.introspect(p1.accessToken()));
        CredentialException e2 = assertThrows(CredentialException.class, () -> service.introspect(p2.accessToken()));
        assertEquals(com.github.h3yow.tokengovernancejava.credential.CredentialErrorType.ACCESS_TOKEN_REVOKED,
                e1.getErrorType());
        assertEquals(com.github.h3yow.tokengovernancejava.credential.CredentialErrorType.ACCESS_TOKEN_REVOKED,
                e2.getErrorType());
        log.info("[revoke-all] both access tokens rejected with ACCESS_TOKEN_REVOKED");
    }

    @Test
    void accessTokenClockSkew_withinLeewayStillValid() {
        TokenPair pair = service.issue("alice", 0L);
        // 凭证 00:10 过期；判本地时钟略快（签发端稍慢），只拨到刚过期但仍在 30s 容忍窗内
        clock.advance(Duration.ofMinutes(10).plusSeconds(20));
        log.info("[skew] now=expiry+20s, leeway=30s, should remain valid");

        var credential = service.introspect(pair.accessToken());
        assertEquals("alice", credential.subjectId());
    }

    @Test
    void accessTokenBeyondLeeway_isClassifiedExpired() {
        TokenPair pair = service.issue("alice", 0L);
        clock.advance(Duration.ofMinutes(10).plusSeconds(45));
        log.info("[skew] now=expiry+45s, beyond leeway=30s, should be EXPIRED");

        CredentialException ex = assertThrows(CredentialException.class,
                () -> service.introspect(pair.accessToken()));
        log.info("[skew] result errorType={}", ex.getErrorType());
        assertEquals(com.github.h3yow.tokengovernancejava.credential.CredentialErrorType.ACCESS_TOKEN_EXPIRED,
                ex.getErrorType());
        assertTrue(ex.getMessage().contains("访问凭证已过期"));
    }

    @Test
    void malformedToken_isClassifiedMalformed() {
        CredentialException ex = assertThrows(CredentialException.class,
                () -> service.introspect("garbage.token"));
        log.info("[malformed] result errorType={}", ex.getErrorType());
        assertEquals(com.github.h3yow.tokengovernancejava.credential.CredentialErrorType.ACCESS_TOKEN_MALFORMED,
                ex.getErrorType());
    }
}

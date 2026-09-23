package com.github.h3yow.tokengovernancejava.tests;

import com.github.h3yow.tokengovernancejava.authz.AccessGuard;
import com.github.h3yow.tokengovernancejava.authz.AuthorizationDecision;
import com.github.h3yow.tokengovernancejava.authz.AuthorizationService;
import com.github.h3yow.tokengovernancejava.authz.DecisionCode;
import com.github.h3yow.tokengovernancejava.authz.Effect;
import com.github.h3yow.tokengovernancejava.authz.PolicyRepository;
import com.github.h3yow.tokengovernancejava.authz.PolicyRule;
import com.github.h3yow.tokengovernancejava.authz.Resource;
import com.github.h3yow.tokengovernancejava.authz.Subject;
import com.github.h3yow.tokengovernancejava.authz.SubjectDirectory;
import com.github.h3yow.tokengovernancejava.token.RejectionReason;
import com.github.h3yow.tokengovernancejava.token.TokenException;
import com.github.h3yow.tokengovernancejava.token.TokenPair;
import com.github.h3yow.tokengovernancejava.token.TokenService;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 端到端访问门卫测试：凭证校验与实时授权联动，
 * 覆盖吊销即时生效与权限调整即时生效。
 */
class AccessGuardTest {

    private static final Logger log = LoggerFactory.getLogger(AccessGuardTest.class);

    private static final long ACCESS_TTL = 60_000L;
    private static final long REFRESH_TTL = 300_000L;
    private static final long SKEW = 30_000L;

    private record Harness(TokenService tokens, SubjectDirectory subjects,
                           PolicyRepository policies, AccessGuard guard) {
    }

    private Harness harness(MutableClock clock) {
        TokenService tokens = new TokenService(ACCESS_TTL, REFRESH_TTL, SKEW, clock);
        SubjectDirectory subjects = new SubjectDirectory();
        PolicyRepository policies = new PolicyRepository();
        AuthorizationService authz = new AuthorizationService(policies, subjects);
        AccessGuard guard = new AccessGuard(tokens, authz);
        return new Harness(tokens, subjects, policies, guard);
    }

    private void logDecision(String input, AuthorizationDecision d) {
        log.info("[门卫输入] {}", input);
        log.info("[门卫结论] permitted={} code={} reason={}", d.permitted(), d.code(), d.reason());
        d.trace().forEach(t -> log.info("[门卫依据] rule={} matched={} effect={} detail={}",
                t.ruleId(), t.matched(), t.effect(), t.detail()));
    }

    @Test
    void valid_token_with_permission_is_permitted() {
        MutableClock clock = new MutableClock(1_000_000L);
        Harness h = harness(clock);
        h.subjects().put(new Subject("alice", Set.of("editor"), Map.of()));
        h.policies().add(new PolicyRule("p1", "edit", "document", "editor",
                null, null, Effect.ALLOW));
        TokenPair pair = h.tokens().issue("alice");
        Resource doc = new Resource("document", Map.of());

        AuthorizationDecision d = h.guard().guard(pair.accessToken().getId(), "edit", doc);
        logDecision("access=" + pair.accessToken().getId() + " action=edit resource=document", d);
        assertTrue(d.permitted());
        assertEquals(DecisionCode.PERMIT, d.code());
    }

    @Test
    void revoked_access_is_denied_on_next_visit() {
        MutableClock clock = new MutableClock(1_000_000L);
        Harness h = harness(clock);
        h.subjects().put(new Subject("alice", Set.of("editor"), Map.of()));
        h.policies().add(new PolicyRule("p1", "edit", "document", "editor",
                null, null, Effect.ALLOW));
        TokenPair pair = h.tokens().issue("alice");
        Resource doc = new Resource("document", Map.of());

        AuthorizationDecision before = h.guard().guard(pair.accessToken().getId(), "edit", doc);
        assertTrue(before.permitted());

        h.tokens().revokeAccess(pair.accessToken().getId());
        log.info("[门卫] 已吊销 access={}", pair.accessToken().getId());

        TokenException ex = assertThrows(TokenException.class,
                () -> h.guard().guard(pair.accessToken().getId(), "edit", doc));
        assertEquals(RejectionReason.REVOKED, ex.getReason());
        log.info("[门卫] 吊销后再次访问被拒 reason={} msg={}", ex.getReason(), ex.getMessage());
    }

    @Test
    void permission_change_takes_effect_without_reissuing_token() {
        MutableClock clock = new MutableClock(1_000_000L);
        Harness h = harness(clock);
        h.subjects().put(new Subject("alice", Set.of("viewer"), Map.of()));
        h.policies().add(new PolicyRule("p1", "edit", "document", "editor",
                null, null, Effect.ALLOW));
        TokenPair pair = h.tokens().issue("alice");
        Resource doc = new Resource("document", Map.of());

        AuthorizationDecision before = h.guard().guard(pair.accessToken().getId(), "edit", doc);
        logDecision("降权前 action=edit", before);
        assertFalse(before.permitted());

        // 同一凭证，主体被提权，下一次访问立即放行（授权信息不缓存于凭证）。
        h.subjects().updateRoles("alice", Set.of("editor"));
        AuthorizationDecision after = h.guard().guard(pair.accessToken().getId(), "edit", doc);
        logDecision("提权后 action=edit（凭证未换）", after);
        assertTrue(after.permitted());

        // 再降权，立即拒绝。
        h.subjects().updateRoles("alice", Set.of("viewer"));
        AuthorizationDecision demoted = h.guard().guard(pair.accessToken().getId(), "edit", doc);
        logDecision("再降权 action=edit（凭证未换）", demoted);
        assertFalse(demoted.permitted());
        assertEquals(DecisionCode.DENY_NO_RULE, demoted.code());
    }
}

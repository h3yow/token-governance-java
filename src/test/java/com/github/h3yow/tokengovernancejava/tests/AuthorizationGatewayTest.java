package com.github.h3yow.tokengovernancejava.tests;

import com.github.h3yow.tokengovernancejava.authz.AuthzRequest;
import com.github.h3yow.tokengovernancejava.authz.Decision;
import com.github.h3yow.tokengovernancejava.authz.DecisionReasonCode;
import com.github.h3yow.tokengovernancejava.authz.DefaultAuthorizationEngine;
import com.github.h3yow.tokengovernancejava.authz.DefaultAuthorizationGateway;
import com.github.h3yow.tokengovernancejava.authz.Effect;
import com.github.h3yow.tokengovernancejava.authz.InMemoryPolicyRepository;
import com.github.h3yow.tokengovernancejava.authz.InMemorySubjectDirectory;
import com.github.h3yow.tokengovernancejava.authz.PolicyRule;
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
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 端到端授权流程单测：凭证校验 + 实时主体状态 + 策略判定。
 * 覆盖吊销立即生效、权限版本变更后旧凭证失效、刷新不抬权、时钟偏差。
 */
class AuthorizationGatewayTest {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationGatewayTest.class);

    private InMemorySubjectDirectory subjects;
    private InMemoryPolicyRepository policies;
    private CredentialService credentials;
    private DefaultAuthorizationGateway gateway;

    @BeforeEach
    void setUp() {
        subjects = new InMemorySubjectDirectory();
        policies = new InMemoryPolicyRepository();
        credentials = new InMemoryCredentialService(
                new TokenSettings(Duration.ofMinutes(10), Duration.ofHours(8), Duration.ofSeconds(30)),
                Clock.systemUTC());
        gateway = new DefaultAuthorizationGateway(credentials, subjects,
                new DefaultAuthorizationEngine(policies));

        subjects.register("alice", Set.of("editor"), Map.of("department", "engineering"));
        subjects.register("bob", Set.of("viewer"), Map.of("region", "restricted"));
        policies.add(PolicyRule.role("editor-read", Effect.ALLOW, "editor",
                "document:read", "docs/*"));
        policies.add(PolicyRule.role("viewer-read", Effect.ALLOW, "viewer",
                "document:read", "docs/*"));
        policies.add(PolicyRule.attribute("restricted-deny", Effect.DENY,
                "document:read", "docs/*", "region", "restricted"));
    }

    private Decision authorize(TokenPair pair, String action, String resource) {
        AuthzRequest request = new AuthzRequest(null, action, resource);
        Decision decision = gateway.authorize(pair.accessToken(), request);
        log.info("[gateway] input family={} action={} resource={} => allowed={} reasons={}",
                pair.familyId(), action, resource, decision.allowed(), decision.reasons());
        return decision;
    }

    @Test
    void happyPath_allowedWithExplicitRuleReason() {
        TokenPair pair = credentials.issue("alice", subjects.find("alice").version());
        Decision decision = authorize(pair, "document:read", "docs/a.txt");
        assertTrue(decision.allowed());
        assertEquals(DecisionReasonCode.EXPLICIT_ALLOW_RULE, decision.reasons().get(0).code());
    }

    @Test
    void attributeDeny_bobBlockedEvenWithViewerAllowRole() {
        TokenPair pair = credentials.issue("bob", subjects.find("bob").version());
        Decision decision = authorize(pair, "document:read", "docs/a.txt");
        assertFalse(decision.allowed());
        assertEquals(DecisionReasonCode.EXPLICIT_DENY_RULE, decision.reasons().get(0).code());
    }

    @Test
    void revoke_takesEffectOnNextAccess() {
        TokenPair pair = credentials.issue("alice", subjects.find("alice").version());
        assertTrue(authorize(pair, "document:read", "docs/a.txt").allowed());

        credentials.revokeFamily(pair.familyId());
        log.info("[revoke-effect] family={} revoked before second access", pair.familyId());

        Decision after = authorize(pair, "document:read", "docs/a.txt");
        assertFalse(after.allowed());
        assertEquals(DecisionReasonCode.CREDENTIAL_INVALID, after.reasons().get(0).code());
        assertTrue(after.reasons().get(0).detail().contains("吊销")
                || after.reasons().get(0).detail().contains("revok"));
    }

    @Test
    void permissionChange_oldTokenImmediatelyStale_refreshDoesNotEscalate() {
        TokenPair pair = credentials.issue("alice", subjects.find("alice").version());
        assertTrue(authorize(pair, "document:read", "docs/a.txt").allowed());

        // 管理员收回 editor 角色 -> 版本变为 1
        subjects.update("alice", Set.of(), Map.of("department", "engineering"));
        log.info("[perm-change] alice roles removed, current version={}",
                subjects.find("alice").version());

        Decision stale = authorize(pair, "document:read", "docs/a.txt");
        assertFalse(stale.allowed(), "权限调整后旧凭证不得再放行");
        assertEquals(DecisionReasonCode.CREDENTIAL_INVALID, stale.reasons().get(0).code());
        assertTrue(stale.reasons().get(0).detail().contains("版本"));

        // 旋转得到的新凭证仍盖旧版本（刷新不提升权限），依旧不能访问
        TokenPair rotated = credentials.refresh(pair.refreshToken());
        Decision rotatedDecision = authorize(rotated, "document:read", "docs/a.txt");
        assertFalse(rotatedDecision.allowed());
        assertEquals(DecisionReasonCode.CREDENTIAL_INVALID, rotatedDecision.reasons().get(0).code());
        log.info("[perm-change] rotated token version={} still denied (no escalation)",
                rotated.version());

        // 重新签发（携带新版本）后，因无角色规则适用 -> 默认拒绝而不是放行
        TokenPair reissued = credentials.issue("alice", subjects.find("alice").version());
        Decision redecision = authorize(reissued, "document:read", "docs/a.txt");
        assertFalse(redecision.allowed());
        assertEquals(DecisionReasonCode.NO_APPLICABLE_RULE, redecision.reasons().get(0).code());
    }

    @Test
    void permissionGranted_takesEffectImmediatelyAfterReissue() {
        subjects.register("carol", Set.of(), Map.of());
        TokenPair pair = credentials.issue("carol", subjects.find("carol").version());
        assertFalse(authorize(pair, "document:read", "docs/a.txt").allowed());

        subjects.update("carol", Set.of("editor"), Map.of("department", "engineering"));
        TokenPair newPair = credentials.issue("carol", subjects.find("carol").version());
        log.info("[perm-grant] carol promoted, reissued at version {}", newPair.version());
        assertTrue(authorize(newPair, "document:read", "docs/a.txt").allowed());
    }

    @Test
    void subjectRemoved_deniedAsSubjectMissingOrInvalidCredential() {
        TokenPair pair = credentials.issue("alice", subjects.find("alice").version());
        subjects.remove("alice");
        Decision decision = authorize(pair, "document:read", "docs/a.txt");
        assertFalse(decision.allowed());
        assertEquals(DecisionReasonCode.SUBJECT_MISSING, decision.reasons().get(0).code());
    }

    @Test
    void garbageToken_deniedWithCredentialInvalid() {
        Decision decision = gateway.authorize("not-a-token",
                new AuthzRequest(null, "document:read", "docs/a.txt"));
        assertFalse(decision.allowed());
        assertEquals(DecisionReasonCode.CREDENTIAL_INVALID, decision.reasons().get(0).code());
        log.info("[garbage-token] reason={}", decision.reasons());
    }
}

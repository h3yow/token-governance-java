package com.github.h3yow.tokengovernancejava.tests;

import com.github.h3yow.tokengovernancejava.authz.AuthzRequest;
import com.github.h3yow.tokengovernancejava.authz.Decision;
import com.github.h3yow.tokengovernancejava.authz.DecisionReasonCode;
import com.github.h3yow.tokengovernancejava.authz.DefaultAuthorizationEngine;
import com.github.h3yow.tokengovernancejava.authz.Effect;
import com.github.h3yow.tokengovernancejava.authz.InMemoryPolicyRepository;
import com.github.h3yow.tokengovernancejava.authz.PolicyRule;
import com.github.h3yow.tokengovernancejava.authz.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 授权判定引擎单测，打印输入角色/属性与判定依据链。 */
class AuthorizationEngineTest {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationEngineTest.class);

    private InMemoryPolicyRepository policies;
    private DefaultAuthorizationEngine engine;

    @BeforeEach
    void setUp() {
        policies = new InMemoryPolicyRepository();
        engine = new DefaultAuthorizationEngine(policies);
        policies.add(PolicyRule.role("editor-read", Effect.ALLOW, "editor",
                "document:read", "docs/*"));
        policies.add(PolicyRule.attribute("engineering-allow", Effect.ALLOW,
                "document:read", "docs/engineering/*", "department", "engineering"));
        policies.add(PolicyRule.attribute("restricted-deny", Effect.DENY,
                "document:read", "docs/*", "region", "restricted"));
        policies.add(PolicyRule.attribute("conf-high-allow", Effect.ALLOW,
                "document:read", "docs/confidential/*", "clearance", "high"));
        policies.add(PolicyRule.attribute("conf-low-deny", Effect.DENY,
                "document:read", "docs/confidential/*", "clearance", "low"));
    }

    private Decision eval(Subject subject, String action, String resource) {
        AuthzRequest request = new AuthzRequest(subject.id(), action, resource);
        Decision decision = engine.evaluate(subject, request);
        log.info("[engine] input subject={} roles={} attrs={} action={} resource={} => allowed={} reasons={}",
                subject.id(), subject.roles(), subject.attributes(), action, resource,
                decision.allowed(), decision.reasons());
        return decision;
    }

    @Test
    void roleAllow_whenOnlyAllowRuleMatches() {
        Subject alice = new Subject("alice", Set.of("editor"), Map.of("department", "engineering"), 0);
        Decision decision = eval(alice, "document:read", "docs/readme.txt");
        assertTrue(decision.allowed());
        assertEquals(DecisionReasonCode.EXPLICIT_ALLOW_RULE, decision.reasons().get(0).code());
    }

    @Test
    void attributeAllow_whenAttributeMatches() {
        Subject carol = new Subject("carol", Set.of(), Map.of("department", "engineering"), 0);
        Decision decision = eval(carol, "document:read", "docs/engineering/spec.md");
        assertTrue(decision.allowed(), "无角色但属性满足应放行");
    }

    @Test
    void explicitDeny_overridesAllow_whenBothRoleAndDenyAttributeMatch() {
        Subject bob = new Subject("bob", Set.of("editor"),
                Map.of("department", "engineering", "region", "restricted"), 0);
        Decision decision = eval(bob, "document:read", "docs/readme.txt");
        assertFalse(decision.allowed());
        assertEquals(DecisionReasonCode.EXPLICIT_DENY_RULE, decision.reasons().get(0).code());
        assertTrue(decision.reasons().stream().anyMatch(r -> r.code() == DecisionReasonCode.CONFLICT_DENY_WINS),
                "允许与拒绝同时存在时必须记录冲突依据");
    }

    @Test
    void defaultDeny_whenNoRuleApplies() {
        Subject dave = new Subject("dave", Set.of("viewer"), Map.of(), 0);
        Decision decision = eval(dave, "document:read", "docs/readme.txt");
        assertFalse(decision.allowed());
        assertEquals(DecisionReasonCode.NO_APPLICABLE_RULE, decision.reasons().get(0).code());
    }

    @Test
    void defaultDeny_whenRulesExistForOtherResource() {
        Subject alice = new Subject("alice", Set.of("editor"), Map.of(), 0);
        Decision decision = eval(alice, "document:delete", "docs/readme.txt");
        assertFalse(decision.allowed());
        assertEquals(DecisionReasonCode.NO_APPLICABLE_RULE, decision.reasons().get(0).code());
    }

    @Test
    void attributeDeny_lowClearanceCannotReadConfidential() {
        Subject erin = new Subject("erin", Set.of("editor"), Map.of("clearance", "low"), 0);
        Decision decision = eval(erin, "document:read", "docs/confidential/x");
        assertFalse(decision.allowed());
        assertTrue(decision.reasons().stream()
                .anyMatch(r -> "conf-low-deny".equals(r.ruleId())));
    }

    @Test
    void attributeAllow_highClearanceCanReadConfidential() {
        Subject frank = new Subject("frank", Set.of("editor"), Map.of("clearance", "high"), 0);
        Decision decision = eval(frank, "document:read", "docs/confidential/x");
        assertTrue(decision.allowed());
    }
}

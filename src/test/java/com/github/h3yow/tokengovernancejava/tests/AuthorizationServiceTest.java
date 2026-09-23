package com.github.h3yow.tokengovernancejava.tests;

import com.github.h3yow.tokengovernancejava.authz.AccessRequest;
import com.github.h3yow.tokengovernancejava.authz.AuthorizationDecision;
import com.github.h3yow.tokengovernancejava.authz.AuthorizationService;
import com.github.h3yow.tokengovernancejava.authz.DecisionCode;
import com.github.h3yow.tokengovernancejava.authz.Effect;
import com.github.h3yow.tokengovernancejava.authz.PolicyRepository;
import com.github.h3yow.tokengovernancejava.authz.PolicyRule;
import com.github.h3yow.tokengovernancejava.authz.Resource;
import com.github.h3yow.tokengovernancejava.authz.Subject;
import com.github.h3yow.tokengovernancejava.authz.SubjectDirectory;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 授权判定测试：角色+属性合取、显式拒绝优先、默认拒绝、冲突拒绝、
 * 主体缺失以及权限调整即时生效。每个用例打印输入与逐条判定依据。
 */
class AuthorizationServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationServiceTest.class);

    private final Resource doc = new Resource("document", Map.of());

    private AuthorizationDecision evaluate(AuthorizationService svc,
                                           String subjectId, String action) {
        AccessRequest req = new AccessRequest(subjectId, action, doc);
        AuthorizationDecision d = svc.decide(req);
        log.info("[判定输入] subject={} action={} resource={}", subjectId, action, doc.name());
        log.info("[判定结论] permitted={} code={} reason={}", d.permitted(), d.code(), d.reason());
        d.trace().forEach(t -> log.info("[判定依据] rule={} matched={} effect={} detail={}",
                t.ruleId(), t.matched(), t.effect(), t.detail()));
        return d;
    }

    private SubjectDirectory directoryWith(Subject... subjects) {
        SubjectDirectory dir = new SubjectDirectory();
        for (Subject s : subjects) {
            dir.put(s);
        }
        return dir;
    }

    @Test
    void role_and_attribute_both_required_for_allow() {
        Subject alice = new Subject("alice", Set.of("editor"),
                Map.of("department", "engineering"));
        PolicyRepository repo = new PolicyRepository();
        // 编辑 + 工程部门 才能编辑文档（角色与属性合取）。
        repo.add(new PolicyRule("r1", "edit", "document", "editor",
                "department", "engineering", Effect.ALLOW));
        AuthorizationService svc = new AuthorizationService(repo, directoryWith(alice));

        AuthorizationDecision ok = evaluate(svc, "alice", "edit");
        assertTrue(ok.permitted());
        assertEquals(DecisionCode.PERMIT, ok.code());

        // 属性不满足：虽有 editor 角色，但部门不符，不允许。
        Subject bob = new Subject("bob", Set.of("editor"), Map.of("department", "sales"));
        SubjectDirectory dir2 = directoryWith(bob);
        AuthorizationService svc2 = new AuthorizationService(repo, dir2);
        AuthorizationDecision noAttr = evaluate(svc2, "bob", "edit");
        assertFalse(noAttr.permitted());
        assertEquals(DecisionCode.DENY_NO_RULE, noAttr.code());

        // 角色不满足：工程部门但不是 editor。
        Subject carol = new Subject("carol", Set.of("viewer"),
                Map.of("department", "engineering"));
        AuthorizationService svc3 = new AuthorizationService(repo, directoryWith(carol));
        AuthorizationDecision noRole = evaluate(svc3, "carol", "edit");
        assertFalse(noRole.permitted());
        assertEquals(DecisionCode.DENY_NO_RULE, noRole.code());
    }

    @Test
    void explicit_deny_overrides_allow() {
        // alice 同时命中“允许 editor”与“显式拒绝黑名单”：拒绝优先，归类为冲突拒绝。
        // bob 只命中允许、不命中拒绝 => 放行。
        PolicyRepository repo = new PolicyRepository();
        repo.add(new PolicyRule("allow-editor", "edit", "document", "editor",
                null, null, Effect.ALLOW));
        repo.add(new PolicyRule("deny-blacklist", "edit", "document", null,
                "blacklisted", "true", Effect.DENY));

        Subject alice = new Subject("alice", Set.of("editor"),
                Map.of("blacklisted", "true"));
        Subject bob = new Subject("bob", Set.of("editor"),
                Map.of("blacklisted", "false"));
        AuthorizationService svc = new AuthorizationService(repo, directoryWith(alice, bob));

        AuthorizationDecision denied = evaluate(svc, "alice", "edit");
        assertFalse(denied.permitted(), "显式拒绝必须压过允许，不得放行");
        assertEquals(DecisionCode.DENY_CONFLICT, denied.code());

        AuthorizationDecision allowed = evaluate(svc, "bob", "edit");
        assertTrue(allowed.permitted(), "未命中拒绝规则的 editor 仍应放行");
        assertEquals(DecisionCode.PERMIT, allowed.code());
    }

    @Test
    void deny_only_match_is_classified_explicit() {
        // 只有一条 DENY 规则、且没有任何 ALLOW 命中时，归类为 DENY_EXPLICIT。
        Subject alice = new Subject("alice", Set.of("editor"),
                Map.of("blacklisted", "true"));
        PolicyRepository repo = new PolicyRepository();
        repo.add(new PolicyRule("deny-blacklist", "edit", "document", null,
                "blacklisted", "true", Effect.DENY));
        AuthorizationService svc = new AuthorizationService(repo, directoryWith(alice));

        AuthorizationDecision d = evaluate(svc, "alice", "edit");
        assertFalse(d.permitted());
        assertEquals(DecisionCode.DENY_EXPLICIT, d.code());
    }

    @Test
    void default_deny_when_no_rule_matches() {
        Subject alice = new Subject("alice", Set.of("guest"), Map.of());
        PolicyRepository repo = new PolicyRepository();
        repo.add(new PolicyRule("r1", "delete", "document", "admin",
                null, null, Effect.ALLOW));
        AuthorizationService svc = new AuthorizationService(repo, directoryWith(alice));

        AuthorizationDecision d = evaluate(svc, "alice", "delete");
        assertFalse(d.permitted());
        assertEquals(DecisionCode.DENY_NO_RULE, d.code(), "规则缺失不得静默放行");
    }

    @Test
    void conflicting_allow_and_deny_is_denied_not_silently_allowed() {
        // 同一请求同时命中一条 ALLOW 与一条 DENY，按冲突拒绝处理。
        Subject alice = new Subject("alice", Set.of("member"), Map.of("flag", "x"));
        PolicyRepository repo = new PolicyRepository();
        repo.add(new PolicyRule("allow-member", "view", "document", "member",
                null, null, Effect.ALLOW));
        repo.add(new PolicyRule("deny-flag", "view", "document", null,
                "flag", "x", Effect.DENY));
        AuthorizationService svc = new AuthorizationService(repo, directoryWith(alice));

        AuthorizationDecision d = evaluate(svc, "alice", "view");
        assertFalse(d.permitted());
        assertEquals(DecisionCode.DENY_CONFLICT, d.code(), "相互冲突时必须拒绝并显式归类");
    }

    @Test
    void missing_subject_is_denied() {
        AuthorizationService svc = new AuthorizationService(new PolicyRepository(),
                new SubjectDirectory());
        AuthorizationDecision d = evaluate(svc, "ghost", "view");
        assertFalse(d.permitted());
        assertEquals(DecisionCode.DENY_SUBJECT_NOT_FOUND, d.code());
    }

    @Test
    void permission_change_takes_effect_immediately() {
        SubjectDirectory dir = directoryWith(new Subject("alice", Set.of("viewer"), Map.of()));
        PolicyRepository repo = new PolicyRepository();
        repo.add(new PolicyRule("allow-edit", "edit", "document", "editor",
                null, null, Effect.ALLOW));
        AuthorizationService svc = new AuthorizationService(repo, dir);

        // 调整前：viewer 不能 edit。
        AuthorizationDecision before = evaluate(svc, "alice", "edit");
        assertFalse(before.permitted());

        // 运行时提权：下一次判定立即生效。
        dir.updateRoles("alice", Set.of("editor"));
        AuthorizationDecision after = evaluate(svc, "alice", "edit");
        assertTrue(after.permitted(), "角色调整后下一次访问应立即放行");
        assertEquals(DecisionCode.PERMIT, after.code());

        // 运行时降权：再次立即失效。
        dir.updateRoles("alice", Set.of("viewer"));
        AuthorizationDecision demoted = evaluate(svc, "alice", "edit");
        assertFalse(demoted.permitted(), "降权后下一次访问必须立即被拒绝");
    }
}

package com.github.h3yow.tokengovernancejava.authz;

import java.util.ArrayList;
import java.util.List;

/**
 * 授权判定服务。
 *
 * <p>判定原则：</p>
 * <ol>
 *   <li>显式拒绝优先于允许；</li>
 *   <li>默认拒绝：无规则命中不得放行；</li>
 *   <li>同一请求同时命中 DENY 与 ALLOW 时，按冲突处理为拒绝（DENY_CONFLICT），绝不静默放行；</li>
 *   <li>结论携带逐条依据，可解释。</li>
 * </ol>
 */
public class AuthorizationService {

    private final PolicyRepository policyRepository;
    private final SubjectDirectory subjectDirectory;

    public AuthorizationService(PolicyRepository policyRepository,
                                SubjectDirectory subjectDirectory) {
        this.policyRepository = policyRepository;
        this.subjectDirectory = subjectDirectory;
    }

    /** 依据主体实时角色与属性进行授权判定。 */
    public AuthorizationDecision decide(AccessRequest request) {
        Subject subject = subjectDirectory.find(request.subjectId());
        if (subject == null) {
            String reason = "主体不存在或已被注销: " + request.subjectId();
            return new AuthorizationDecision(false, DecisionCode.DENY_SUBJECT_NOT_FOUND,
                    reason, List.of());
        }

        List<DecisionTrace> trace = new ArrayList<>();
        List<PolicyRule> matchedAllows = new ArrayList<>();
        List<PolicyRule> matchedDenies = new ArrayList<>();

        for (PolicyRule rule : policyRepository.all()) {
            boolean matched = rule.matches(request, subject);
            trace.add(new DecisionTrace(rule.id(), matched, rule.effect(),
                    matched ? describeMatch(rule) : describeMiss(rule, request, subject)));
            if (matched) {
                if (rule.effect() == Effect.DENY) {
                    matchedDenies.add(rule);
                } else {
                    matchedAllows.add(rule);
                }
            }
        }

        // 显式拒绝优先；允许与拒绝同时命中视为冲突，拒绝而非静默放行。
        if (!matchedDenies.isEmpty() && !matchedAllows.isEmpty()) {
            return new AuthorizationDecision(false, DecisionCode.DENY_CONFLICT,
                    "规则冲突：同时命中显式拒绝 " + ids(matchedDenies)
                            + " 与允许 " + ids(matchedAllows) + "，按拒绝优先处理",
                    trace);
        }
        if (!matchedDenies.isEmpty()) {
            return new AuthorizationDecision(false, DecisionCode.DENY_EXPLICIT,
                    "命中显式拒绝规则: " + ids(matchedDenies), trace);
        }
        if (!matchedAllows.isEmpty()) {
            return new AuthorizationDecision(true, DecisionCode.PERMIT,
                    "命中允许规则: " + ids(matchedAllows), trace);
        }
        return new AuthorizationDecision(false, DecisionCode.DENY_NO_RULE,
                "默认拒绝：没有任何规则命中该请求", trace);
    }

    private String describeMatch(PolicyRule rule) {
        StringBuilder sb = new StringBuilder("命中：动作=").append(rule.action())
                .append("，资源=").append(rule.resourceName());
        if (rule.requiredRole() != null) {
            sb.append("，角色满足[").append(rule.requiredRole()).append(']');
        }
        if (rule.attributeName() != null) {
            sb.append("，属性满足[").append(rule.attributeName())
                    .append('=').append(rule.attributeValue()).append(']');
        }
        sb.append(" => ").append(rule.effect());
        return sb.toString();
    }

    private String describeMiss(PolicyRule rule, AccessRequest request, Subject subject) {
        if (!rule.action().equals(request.action())) {
            return "未命中：动作不符（规则=" + rule.action()
                    + "，请求=" + request.action() + '）';
        }
        if (!rule.resourceName().equals(request.resource().name())) {
            return "未命中：资源不符（规则=" + rule.resourceName()
                    + "，请求=" + request.resource().name() + '）';
        }
        if (rule.requiredRole() != null && !subject.roles().contains(rule.requiredRole())) {
            return "未命中：缺少所需角色[" + rule.requiredRole()
                    + "]，当前角色=" + subject.roles();
        }
        if (rule.attributeName() != null) {
            Object actual = subject.attributes().get(rule.attributeName());
            boolean ok = rule.attributeValue() == null
                    ? actual == null
                    : rule.attributeValue().equals(actual);
            if (!ok) {
                return "未命中：属性[" + rule.attributeName() + "]期望="
                        + rule.attributeValue() + "，实际=" + actual;
            }
        }
        return "未命中";
    }

    private String ids(List<PolicyRule> rules) {
        return rules.stream().map(PolicyRule::id).toList().toString();
    }
}

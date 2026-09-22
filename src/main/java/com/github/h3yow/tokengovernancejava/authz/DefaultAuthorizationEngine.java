package com.github.h3yow.tokengovernancejava.authz;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * 默认判定引擎。
 *
 * <p>判定流程：</p>
 * <ol>
 *   <li>找出全部适用规则：动作、资源匹配 <b>且</b> 角色或属性条件满足；</li>
 *   <li>只要存在任意显式拒绝规则即拒绝（显式拒绝优先于允许）；</li>
 *   <li>拒绝与允许规则同时存在属于冲突，仍拒绝，并额外记录 CONFLICT_DENY_WINS 依据；</li>
 *   <li>仅存在允许规则才放行；一条适用规则都没有则默认拒绝（NO_APPLICABLE_RULE）。</li>
 * </ol>
 * <p>任何路径都不会静默放行，且结论附带完整依据链。</p>
 */
@Component
public class DefaultAuthorizationEngine implements AuthorizationEngine {

    private static final Logger log = LoggerFactory.getLogger(DefaultAuthorizationEngine.class);

    private final PolicyRepository policyRepository;

    public DefaultAuthorizationEngine(PolicyRepository policyRepository) {
        this.policyRepository = policyRepository;
    }

    @Override
    public Decision evaluate(Subject subject, AuthzRequest request) {
        List<DecisionReason> denyReasons = new ArrayList<>();
        List<DecisionReason> allowReasons = new ArrayList<>();

        for (PolicyRule rule : applicableRules(subject, request)) {
            String detail = "rule " + rule.id()
                    + " kind=" + rule.kind()
                    + " action=" + rule.action()
                    + " resource=" + rule.resource();
            if (rule.effect() == Effect.DENY) {
                denyReasons.add(new DecisionReason(
                        DecisionReasonCode.EXPLICIT_DENY_RULE, rule.kind(), rule.id(), detail));
            } else {
                allowReasons.add(new DecisionReason(
                        DecisionReasonCode.EXPLICIT_ALLOW_RULE, rule.kind(), rule.id(), detail));
            }
        }

        Decision decision;
        if (!denyReasons.isEmpty()) {
            List<DecisionReason> reasons = new ArrayList<>(denyReasons);
            if (!allowReasons.isEmpty()) {
                reasons.add(DecisionReason.of(DecisionReasonCode.CONFLICT_DENY_WINS,
                        "同时命中 " + denyReasons.size() + " 条拒绝规则与 "
                                + allowReasons.size() + " 条允许规则，按显式拒绝优先处理"));
            }
            decision = Decision.deny(request, reasons);
        } else if (!allowReasons.isEmpty()) {
            decision = Decision.allow(request, allowReasons);
        } else {
            decision = Decision.deny(request, List.of(DecisionReason.of(
                    DecisionReasonCode.NO_APPLICABLE_RULE,
                    "没有任何角色或属性规则适用于 action=" + request.action()
                            + ", resource=" + request.resource())));
        }

        log.info("authz-evaluate subject={} roles={} attrs={} request=({},{}) => allowed={} reasons={}",
                subject.id(), subject.roles(), subject.attributes(),
                request.action(), request.resource(), decision.allowed(), decision.reasons());
        return decision;
    }

    private List<PolicyRule> applicableRules(Subject subject, AuthzRequest request) {
        List<PolicyRule> matched = new ArrayList<>();
        for (PolicyRule rule : policyRepository.findAll()) {
            if (rule.matchesActionResource(request.action(), request.resource())
                    && rule.matchesSubject(subject.roles(), subject.attributes())) {
                matched.add(rule);
            }
        }
        return matched;
    }
}

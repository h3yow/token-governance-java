package com.github.h3yow.tokengovernancejava.authz;

import java.util.Map;
import java.util.Set;

/**
 * 一条授权策略规则。
 *
 * @param id       规则标识（解释判定依据时引用）
 * @param kind     依据类别：角色或属性
 * @param effect   显式允许或显式拒绝
 * @param action   匹配动作；"*" 表示匹配任意动作
 * @param resource 匹配资源；精确串、"*" 或以 "/*" 结尾的前缀
 * @param key      ROLE 规则时为 "role:" + 角色名；ATTRIBUTE 规则时为属性名
 * @param value    ATTRIBUTE 规则时要求属性等于该值；为 null 表示只要求属性存在
 */
public record PolicyRule(
        String id,
        RuleKind kind,
        Effect effect,
        String action,
        String resource,
        String key,
        String value
) {

    private static final String ROLE_PREFIX = "role:";

    /** 便捷构造：基于角色的规则。 */
    public static PolicyRule role(String id, Effect effect, String role, String action, String resource) {
        return new PolicyRule(id, RuleKind.ROLE, effect, action, resource, ROLE_PREFIX + role, null);
    }

    /** 便捷构造：基于属性的规则（要求 key=value）。 */
    public static PolicyRule attribute(String id, Effect effect, String action, String resource,
                                       String key, String value) {
        return new PolicyRule(id, RuleKind.ATTRIBUTE, effect, action, resource, key, value);
    }

    /** 判断规则的动作与资源维度是否匹配本次请求。 */
    public boolean matchesActionResource(String requestedAction, String requestedResource) {
        boolean actionOk = "*".equals(action) || action.equals(requestedAction);
        boolean resourceOk = matchesResource(requestedResource);
        return actionOk && resourceOk;
    }

    private boolean matchesResource(String requestedResource) {
        if ("*".equals(resource)) {
            return true;
        }
        if (resource.endsWith("/*")) {
            String prefix = resource.substring(0, resource.length() - 1); // 保留结尾 '/'
            return requestedResource.startsWith(prefix);
        }
        return resource.equals(requestedResource);
    }

    /** 判断规则的主体维度（角色或属性）是否适用于给定主体。 */
    public boolean matchesSubject(Set<String> roles, Map<String, String> attributes) {
        if (kind == RuleKind.ROLE) {
            String roleName = key.substring(ROLE_PREFIX.length());
            return roles.contains(roleName);
        }
        if (!attributes.containsKey(key)) {
            return false;
        }
        return value == null || value.equals(attributes.get(key));
    }
}

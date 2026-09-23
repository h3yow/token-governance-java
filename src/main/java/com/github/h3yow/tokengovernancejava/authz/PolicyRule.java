package com.github.h3yow.tokengovernancejava.authz;

/**
 * 单条授权规则。
 *
 * <p>匹配语义（合取）：</p>
 * <ul>
 *   <li>action 必须与请求动作相等；</li>
 *   <li>resourceName 必须与资源名相等；</li>
 *   <li>requiredRole 非空时，主体必须拥有该角色；</li>
 *   <li>attributeName 非空时，主体对应属性必须等于 attributeValue（基于主体实时状态）。</li>
 * </ul>
 * 角色条件与属性条件都满足（或未配置）时规则才命中。
 */
public record PolicyRule(String id,
                         String action,
                         String resourceName,
                         String requiredRole,
                         String attributeName,
                         String attributeValue,
                         Effect effect) {

    /** 是否命中给定请求与主体（属性取自主体实时状态）。 */
    public boolean matches(AccessRequest request, Subject subject) {
        if (!action.equals(request.action())) {
            return false;
        }
        if (!resourceName.equals(request.resource().name())) {
            return false;
        }
        if (requiredRole != null && !subject.roles().contains(requiredRole)) {
            return false;
        }
        if (attributeName != null) {
            String actual = subject.attributes().get(attributeName);
            return attributeValue == null ? actual == null : attributeValue.equals(actual);
        }
        return true;
    }
}

package com.github.h3yow.tokengovernancejava.authz;

import java.util.Map;
import java.util.Set;

/**
 * 主体的实时状态：角色与属性。判定时即时读取，保证权限调整立刻生效。
 */
public record Subject(String id, Set<String> roles, Map<String, String> attributes) {

    public Subject {
        roles = Set.copyOf(roles);
        attributes = Map.copyOf(attributes);
    }
}

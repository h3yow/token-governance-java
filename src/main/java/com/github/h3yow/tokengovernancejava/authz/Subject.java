package com.github.h3yow.tokengovernancejava.authz;

import java.util.Map;
import java.util.Set;

/**
 * 授权主体：角色集合 + 属性集合。属性调整即产生新的版本号。
 */
public record Subject(
        String id,
        Set<String> roles,
        Map<String, String> attributes,
        long version
) {
}

package com.github.h3yow.tokengovernancejava.web.dto;

import java.util.Set;

/** 角色调整请求。 */
public record UpdateRolesRequest(String subject, Set<String> roles) {
}

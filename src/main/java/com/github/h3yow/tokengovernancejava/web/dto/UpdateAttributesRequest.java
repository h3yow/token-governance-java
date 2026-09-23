package com.github.h3yow.tokengovernancejava.web.dto;

import java.util.Map;

/** 属性调整请求。 */
public record UpdateAttributesRequest(String subject, Map<String, String> attributes) {
}

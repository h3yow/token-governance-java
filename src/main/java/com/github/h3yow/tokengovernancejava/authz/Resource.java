package com.github.h3yow.tokengovernancejava.authz;

import java.util.Map;

/** 被访问资源及其环境属性。 */
public record Resource(String name, Map<String, String> attributes) {

    public Resource {
        attributes = Map.copyOf(attributes);
    }
}

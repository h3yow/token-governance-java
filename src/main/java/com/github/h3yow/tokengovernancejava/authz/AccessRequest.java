package com.github.h3yow.tokengovernancejava.authz;

/**
 * 一次访问判定输入：谁 对什么资源 做什么动作。
 */
public record AccessRequest(String subjectId, String action, Resource resource) {
}

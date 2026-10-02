package com.github.h3yow.tokengovernancejava.web.dto;

/**
 * 签发请求。
 *
 * @param subject 主体
 * @param device  可选的设备/来源标识；缺省（老客户端）按 default 会话处理
 */
public record IssueRequest(String subject, String device) {
}

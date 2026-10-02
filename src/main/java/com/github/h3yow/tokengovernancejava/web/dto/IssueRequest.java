package com.github.h3yow.tokengovernancejava.web.dto;

/**
 * 签发请求。
 *
 * @param subject     主体（必填）
 * @param deviceLabel 设备/来源标识（可选）；老客户端不传时按默认会话处理
 */
public record IssueRequest(String subject, String deviceLabel) {
}

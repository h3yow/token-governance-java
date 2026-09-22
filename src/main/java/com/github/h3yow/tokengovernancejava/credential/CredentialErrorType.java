package com.github.h3yow.tokengovernancejava.credential;

/**
 * 凭证相关错误的明确归类。每一类都对应一种可区分的拒绝原因，
 * 调用方与日志可以依据该枚举给出确定、可解释的结论。
 */
public enum CredentialErrorType {

    /** 刷新凭证不存在（未知凭证，或其所属会话已被重放检测清除）。 */
    REFRESH_TOKEN_NOT_FOUND,

    /** 刷新凭证已在之前的旋转中被成功消费，再次使用属于重放。 */
    REFRESH_TOKEN_CONSUMED,

    /** 刷新凭证已超过有效期。 */
    REFRESH_TOKEN_EXPIRED,

    /** 凭证所属会话/凭证族已被管理员吊销。 */
    SESSION_REVOKED,

    /** 访问凭证格式非法或签名不通过。 */
    ACCESS_TOKEN_MALFORMED,

    /** 访问凭证已过期（且超出时钟偏差容忍窗口）。 */
    ACCESS_TOKEN_EXPIRED,

    /** 访问凭证所属会话已吊销，或主体权限版本已变更（旧凭证失效）。 */
    ACCESS_TOKEN_REVOKED,

    /** 主体不存在（已被删除）。 */
    SUBJECT_NOT_FOUND
}

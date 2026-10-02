package com.github.h3yow.tokengovernancejava.session;

/** 会话操作被拒绝的可区分原因。 */
public enum SessionRejection {
    /** 会话不存在或已结束。 */
    SESSION_NOT_FOUND,
    /** 该用户同时存在的有效会话数已达上限。 */
    SESSION_LIMIT_EXCEEDED
}

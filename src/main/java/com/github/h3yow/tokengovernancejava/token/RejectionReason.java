package com.github.h3yow.tokengovernancejava.token;

/**
 * 凭证被拒绝的可区分原因。
 * 不同原因互不重叠，调用方可据此做不同处理与日志归因。
 */
public enum RejectionReason {
    NOT_FOUND,
    ALREADY_CONSUMED,
    EXPIRED,
    REVOKED,
    WRONG_TYPE,
    REPLAY_DETECTED
}

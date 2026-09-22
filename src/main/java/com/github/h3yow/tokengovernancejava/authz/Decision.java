package com.github.h3yow.tokengovernancejava.authz;

import java.util.List;

/**
 * 授权判定的最终结论：允许/拒绝 + 完整可解释依据链。
 */
public record Decision(
        boolean allowed,
        AuthzRequest request,
        List<DecisionReason> reasons
) {

    /** 构造一个拒绝结论。 */
    public static Decision deny(AuthzRequest request, List<DecisionReason> reasons) {
        return new Decision(false, request, List.copyOf(reasons));
    }

    /** 构造一个允许结论。 */
    public static Decision allow(AuthzRequest request, List<DecisionReason> reasons) {
        return new Decision(true, request, List.copyOf(reasons));
    }
}

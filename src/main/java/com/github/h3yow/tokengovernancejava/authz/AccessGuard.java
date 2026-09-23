package com.github.h3yow.tokengovernancejava.authz;

import com.github.h3yow.tokengovernancejava.token.AccessValidation;
import com.github.h3yow.tokengovernancejava.token.TokenService;

/**
 * 访问门卫：把凭证校验与授权判定串成一次完整的访问结论。
 *
 * <p>每次访问都即时校验凭证状态并即时读取主体最新角色/属性，
 * 因此吊销或权限调整在下一次访问即生效，不依赖旧凭证内缓存的授权信息。</p>
 */
public class AccessGuard {

    private final TokenService tokenService;
    private final AuthorizationService authorizationService;

    public AccessGuard(TokenService tokenService,
                       AuthorizationService authorizationService) {
        this.tokenService = tokenService;
        this.authorizationService = authorizationService;
    }

    /**
     * 校验访问凭证并判定授权。凭证非法时由 {@code TokenService} 抛出
     * {@link com.github.h3yow.tokengovernancejava.token.TokenException}（原因可区分）；
     * 凭证合法但授权不通过时返回 {@code permitted=false} 的可解释结论。
     */
    public AuthorizationDecision guard(String accessTokenId, String action, Resource resource) {
        AccessValidation validation = tokenService.validateAccess(accessTokenId);
        AccessRequest request = new AccessRequest(validation.subject(), action, resource);
        return authorizationService.decide(request);
    }
}

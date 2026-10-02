package com.github.h3yow.tokengovernancejava.web;

import com.github.h3yow.tokengovernancejava.authz.AccessGuard;
import com.github.h3yow.tokengovernancejava.authz.AuthorizationDecision;
import com.github.h3yow.tokengovernancejava.authz.Resource;
import com.github.h3yow.tokengovernancejava.session.SessionService;
import com.github.h3yow.tokengovernancejava.session.SessionView;
import com.github.h3yow.tokengovernancejava.token.TokenPair;
import com.github.h3yow.tokengovernancejava.token.TokenService;
import com.github.h3yow.tokengovernancejava.web.dto.CheckRequest;
import com.github.h3yow.tokengovernancejava.web.dto.CheckResponse;
import com.github.h3yow.tokengovernancejava.web.dto.EndAllSessionsRequest;
import com.github.h3yow.tokengovernancejava.web.dto.EndSessionRequest;
import com.github.h3yow.tokengovernancejava.web.dto.IssueRequest;
import com.github.h3yow.tokengovernancejava.web.dto.RefreshRequest;
import com.github.h3yow.tokengovernancejava.web.dto.RevokeRequest;
import com.github.h3yow.tokengovernancejava.web.dto.TokenPairResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** 凭证签发 / 刷新 / 吊销 / 会话管理 / 授权判定 的本地 HTTP 接口。 */
@RestController
@RequestMapping("/api")
public class GovernanceController {

    private final TokenService tokenService;
    private final AccessGuard accessGuard;
    private final SessionService sessionService;

    public GovernanceController(TokenService tokenService, AccessGuard accessGuard,
                                SessionService sessionService) {
        this.tokenService = tokenService;
        this.accessGuard = accessGuard;
        this.sessionService = sessionService;
    }

    /** 签发一对新凭证；可携带设备/来源标识，缺省按 default 会话处理。 */
    @PostMapping("/tokens")
    public TokenPairResponse issue(@RequestBody IssueRequest request) {
        if (request == null || request.subject() == null || request.subject().isBlank()) {
            throw new IllegalArgumentException("subject 不能为空");
        }
        return toResponse(tokenService.issue(request.subject(), request.device()));
    }

    /** 旋转刷新：同一刷新凭证并发使用最多成功一次。 */
    @PostMapping("/tokens/refresh")
    public TokenPairResponse refresh(@RequestBody RefreshRequest request) {
        if (request == null || request.refreshToken() == null || request.refreshToken().isBlank()) {
            throw new IllegalArgumentException("refreshToken 不能为空");
        }
        return toResponse(tokenService.rotate(request.refreshToken()));
    }

    /** 吊销：同时支持访问凭证与刷新凭证，按家族整链失效。 */
    @PostMapping("/tokens/revoke")
    public Map<String, Object> revoke(@RequestBody RevokeRequest request) {
        if (request == null || request.token() == null || request.token().isBlank()) {
            throw new IllegalArgumentException("token 不能为空");
        }
        String id = request.token();
        // 按 token 类型选择吊销入口；类型错误时 TokenService 给出可区分原因。
        try {
            tokenService.revokeRefresh(id);
        } catch (com.github.h3yow.tokengovernancejava.token.TokenException ex) {
            if (ex.getReason()
                    == com.github.h3yow.tokengovernancejava.token.RejectionReason.WRONG_TYPE) {
                tokenService.revokeAccess(id);
            } else {
                throw ex;
            }
        }
        return Map.of("revoked", true, "token", id);
    }

    /** 授权判定：返回放行/拒绝结论、归类码与逐条依据。 */
    @PostMapping("/check")
    public CheckResponse check(@RequestBody CheckRequest request) {
        if (request == null || request.accessToken() == null || request.action() == null
                || request.resource() == null) {
            throw new IllegalArgumentException("accessToken/action/resource 均不能为空");
        }
        Resource resource = new Resource(request.resource(), Map.of());
        AuthorizationDecision decision =
                accessGuard.guard(request.accessToken(), request.action(), resource);
        return CheckResponse.from(decision);
    }

    /** 查看某用户当前有效会话清单（只含元信息，不含凭证）。 */
    @GetMapping("/sessions")
    public List<SessionView> listSessions(@RequestParam String subject) {
        return sessionService.listSessions(subject);
    }

    /** 单独结束某个会话，立即生效；不存在或已结束返回 404。 */
    @PostMapping("/sessions/end")
    public Map<String, Object> endSession(@RequestBody EndSessionRequest request) {
        if (request == null || request.sessionId() == null || request.sessionId().isBlank()) {
            throw new IllegalArgumentException("sessionId 不能为空");
        }
        sessionService.endSession(request.sessionId());
        return Map.of("ended", true, "sessionId", request.sessionId());
    }

    /** 结束某用户的全部会话，返回结束的会话数。 */
    @PostMapping("/sessions/end-all")
    public Map<String, Object> endAllSessions(@RequestBody EndAllSessionsRequest request) {
        if (request == null || request.subject() == null || request.subject().isBlank()) {
            throw new IllegalArgumentException("subject 不能为空");
        }
        int ended = sessionService.endAllSessions(request.subject());
        return Map.of("ended", ended, "subject", request.subject());
    }

    private TokenPairResponse toResponse(TokenPair pair) {
        return new TokenPairResponse(
                pair.accessToken().getId(),
                pair.refreshToken().getId(),
                pair.accessToken().getExpiresAt(),
                pair.refreshToken().getExpiresAt(),
                pair.accessToken().getFamilyId());
    }
}

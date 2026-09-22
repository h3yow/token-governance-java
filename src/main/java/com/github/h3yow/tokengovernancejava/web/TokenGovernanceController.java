package com.github.h3yow.tokengovernancejava.web;

import com.github.h3yow.tokengovernancejava.authz.AuthzRequest;
import com.github.h3yow.tokengovernancejava.authz.AuthorizationGateway;
import com.github.h3yow.tokengovernancejava.authz.Decision;
import com.github.h3yow.tokengovernancejava.authz.PolicyRepository;
import com.github.h3yow.tokengovernancejava.authz.PolicyRule;
import com.github.h3yow.tokengovernancejava.authz.Subject;
import com.github.h3yow.tokengovernancejava.authz.SubjectDirectory;
import com.github.h3yow.tokengovernancejava.credential.CredentialService;
import com.github.h3yow.tokengovernancejava.credential.TokenPair;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Set;

/** 本地演示用 REST 接口：签发/刷新/吊销/判定/主体与策略管理。 */
@RestController
@RequestMapping("/api")
public class TokenGovernanceController {

    private final CredentialService credentialService;
    private final AuthorizationGateway gateway;
    private final SubjectDirectory subjectDirectory;
    private final PolicyRepository policyRepository;

    public TokenGovernanceController(CredentialService credentialService,
                                     AuthorizationGateway gateway,
                                     SubjectDirectory subjectDirectory,
                                     PolicyRepository policyRepository) {
        this.credentialService = credentialService;
        this.gateway = gateway;
        this.subjectDirectory = subjectDirectory;
        this.policyRepository = policyRepository;
    }

    /** 注册主体（角色 + 属性）。 */
    @PostMapping("/subjects")
    public Subject registerSubject(@RequestBody SubjectBody body) {
        return subjectDirectory.register(body.subjectId(),
                body.roles() == null ? Set.of() : Set.copyOf(body.roles()),
                body.attributes() == null ? Map.of() : Map.copyOf(body.attributes()));
    }

    /** 调整主体角色/属性（版本号 +1，旧凭证立即失效）。 */
    @PostMapping("/subjects/{id}/permissions")
    public Subject updatePermissions(@PathVariable String id, @RequestBody SubjectBody body) {
        return subjectDirectory.update(id,
                body.roles() == null ? Set.of() : Set.copyOf(body.roles()),
                body.attributes() == null ? Map.of() : Map.copyOf(body.attributes()));
    }

    /** 签发凭证：使用主体当前版本盖章。 */
    @PostMapping("/tokens/issue")
    public TokenPair issue(@RequestBody SubjectRef body) {
        Subject subject = requireSubject(body.subjectId());
        return credentialService.issue(subject.id(), subject.version());
    }

    /** 刷新凭证（一次性，并发仅一个成功）。 */
    @PostMapping("/tokens/refresh")
    public TokenPair refresh(@RequestBody TokenRef body) {
        return credentialService.refresh(body.refreshToken());
    }

    /** 吊销某个凭证族（会话）。 */
    @PostMapping("/tokens/revoke-family")
    public Map<String, String> revokeFamily(@RequestBody FamilyRef body) {
        credentialService.revokeFamily(body.familyId());
        return Map.of("status", "revoked", "familyId", body.familyId());
    }

    /** 吊销主体全部会话。 */
    @PostMapping("/subjects/{id}/revoke")
    public Map<String, String> revokeSubject(@PathVariable String id) {
        credentialService.revokeAllForSubject(id);
        return Map.of("status", "revoked", "subjectId", id);
    }

    /** 授权判定。访问凭证放 Bearer 头；返回允许/拒绝与完整依据链。 */
    @PostMapping("/authorize")
    public Decision authorize(@RequestHeader(name = "Authorization", required = false) String authorization,
                            @RequestBody AuthorizeBody body) {
        String token = bearer(authorization);
        // 主体身份以凭证为准，请求方无法通过请求体伪造 subjectId
        return gateway.authorize(token, new AuthzRequest(null, body.action(), body.resource()));
    }

    /** 查询全部策略规则。 */
    @GetMapping("/policies")
    public List<PolicyRule> listPolicies() {
        return policyRepository.findAll();
    }

    private Subject requireSubject(String id) {
        Subject subject = subjectDirectory.find(id);
        if (subject == null) {
            throw new IllegalArgumentException("主体不存在：" + id);
        }
        return subject;
    }

    private static String bearer(String authorization) {
        if (authorization == null || authorization.isBlank()) {
            return "";
        }
        return authorization.startsWith("Bearer ") ? authorization.substring(7) : authorization;
    }

    public record SubjectBody(String subjectId, Set<String> roles, Map<String, String> attributes) {
    }

    public record SubjectRef(String subjectId) {
    }

    public record TokenRef(String refreshToken) {
    }

    public record FamilyRef(String familyId) {
    }

    public record AuthorizeBody(String action, String resource) {
    }
}

package com.github.h3yow.tokengovernancejava.authz;

import com.github.h3yow.tokengovernancejava.credential.AccessCredential;
import com.github.h3yow.tokengovernancejava.credential.CredentialException;
import com.github.h3yow.tokengovernancejava.credential.CredentialService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 默认授权入口。
 *
 * <p>每次访问实时执行：</p>
 * <ol>
 *   <li>解析并校验访问凭证（签名、时钟偏差容忍后的过期判断、会话吊销状态）；</li>
 *   <li>从主体目录读取主体<b>当前</b>角色/属性与版本：主体被删除则拒绝；
 *       主体权限版本已高于凭证盖章版本，说明签发后发生过权限调整，旧凭证立即失效；</li>
 *   <li>把最新主体状态交给判定引擎，得到可解释结论。</li>
 * </ol>
 * 因此吊销或权限调整之后，后续访问不会再被放行；不存在"旧状态缓存"造成的越权窗口。
 */
@Component
public class DefaultAuthorizationGateway implements AuthorizationGateway {

    private static final Logger log = LoggerFactory.getLogger(DefaultAuthorizationGateway.class);

    private final CredentialService credentialService;
    private final SubjectDirectory subjectDirectory;
    private final AuthorizationEngine engine;

    public DefaultAuthorizationGateway(CredentialService credentialService,
                                   SubjectDirectory subjectDirectory,
                                   AuthorizationEngine engine) {
        this.credentialService = credentialService;
        this.subjectDirectory = subjectDirectory;
        this.engine = engine;
    }

    @Override
    public Decision authorize(String accessToken, AuthzRequest request) {
        AccessCredential credential;
        try {
            credential = credentialService.introspect(accessToken);
        } catch (CredentialException e) {
            Decision decision = Decision.deny(request, List.of(DecisionReason.of(
                    DecisionReasonCode.CREDENTIAL_INVALID,
                    "访问凭证无效：" + e.getErrorType() + " - " + e.getMessage())));
            log.info("authz-deny request=({},{}) reason=credential invalid type={} detail={}",
                    request.action(), request.resource(), e.getErrorType(), e.getMessage());
            return decision;
        }

        Subject subject = subjectDirectory.find(credential.subjectId());
        if (subject == null) {
            Decision decision = Decision.deny(request, List.of(DecisionReason.of(
                    DecisionReasonCode.SUBJECT_MISSING,
                    "主体不存在或已被删除：" + credential.subjectId())));
            log.info("authz-deny request=({},{}) subject={} reason=subject missing",
                    request.action(), request.resource(), credential.subjectId());
            return decision;
        }

        if (subject.version() != credential.version()) {
            Decision decision = Decision.deny(request, List.of(DecisionReason.of(
                    DecisionReasonCode.CREDENTIAL_INVALID,
                    "主体权限版本已变更：凭证版本=" + credential.version()
                            + "，当前版本=" + subject.version() + "，旧凭证失效")));
            log.info("authz-deny request=({},{}) subject={} reason=stale version token={} current={}",
                    request.action(), request.resource(), subject.id(),
                    credential.version(), subject.version());
            return decision;
        }

        Decision decision = engine.evaluate(subject, request);
        log.info("authz-gateway subject={} request=({},{}) allowed={} reasons={}",
                subject.id(), request.action(), request.resource(),
                decision.allowed(), decision.reasons());
        return decision;
    }
}

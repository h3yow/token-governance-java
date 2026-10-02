package com.github.h3yow.tokengovernancejava.config;

import com.github.h3yow.tokengovernancejava.authz.AccessGuard;
import com.github.h3yow.tokengovernancejava.authz.AuthorizationService;
import com.github.h3yow.tokengovernancejava.authz.PolicyRepository;
import com.github.h3yow.tokengovernancejava.authz.SubjectDirectory;
import com.github.h3yow.tokengovernancejava.token.TokenService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/** 凭证、会话与授权组件的 Spring 装配。 */
@Configuration
public class GovernanceConfig {

    /** 访问凭证有效期：10 分钟。 */
    public static final long ACCESS_TTL_MILLIS = 10 * 60 * 1000L;

    /** 刷新凭证有效期：8 小时。 */
    public static final long REFRESH_TTL_MILLIS = 8 * 60 * 60 * 1000L;

    /** 时钟偏差容忍：避免轻微时钟偏差把有效凭证误判为过期（30 秒）。 */
    public static final long CLOCK_SKEW_MILLIS = 30_000L;

    /**
     * 每个主体可同时存在的有效登录会话（设备）数上限。
     * 可通过配置项 {@code token-governance.max-sessions-per-subject} 覆盖。
     */
    @Value("${token-governance.max-sessions-per-subject:5}")
    private int maxSessionsPerSubject;

    @Bean
    public Clock systemClock() {
        return Clock.systemUTC();
    }

    @Bean
    public TokenService tokenService(Clock clock) {
        return new TokenService(ACCESS_TTL_MILLIS, REFRESH_TTL_MILLIS,
                CLOCK_SKEW_MILLIS, maxSessionsPerSubject, clock);
    }

    @Bean
    public SubjectDirectory subjectDirectory() {
        return new SubjectDirectory();
    }

    @Bean
    public PolicyRepository policyRepository() {
        return new PolicyRepository();
    }

    @Bean
    public AuthorizationService authorizationService(PolicyRepository policyRepository,
                                                      SubjectDirectory subjectDirectory) {
        return new AuthorizationService(policyRepository, subjectDirectory);
    }

    @Bean
    public AccessGuard accessGuard(TokenService tokenService,
                                   AuthorizationService authorizationService) {
        return new AccessGuard(tokenService, authorizationService);
    }
}

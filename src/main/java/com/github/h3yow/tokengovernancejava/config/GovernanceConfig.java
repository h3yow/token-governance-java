package com.github.h3yow.tokengovernancejava.config;

import com.github.h3yow.tokengovernancejava.authz.AccessGuard;
import com.github.h3yow.tokengovernancejava.authz.AuthorizationService;
import com.github.h3yow.tokengovernancejava.authz.PolicyRepository;
import com.github.h3yow.tokengovernancejava.authz.SubjectDirectory;
import com.github.h3yow.tokengovernancejava.session.SessionRegistry;
import com.github.h3yow.tokengovernancejava.session.SessionService;
import com.github.h3yow.tokengovernancejava.token.TokenService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/** 凭证与授权组件的 Spring 装配。 */
@Configuration
public class GovernanceConfig {

    /** 访问凭证有效期：10 分钟。 */
    public static final long ACCESS_TTL_MILLIS = 10 * 60 * 1000L;

    /** 刷新凭证有效期：8 小时。 */
    public static final long REFRESH_TTL_MILLIS = 8 * 60 * 60 * 1000L;

    /** 时钟偏差容忍：避免轻微时钟偏差把有效凭证误判为过期（30 秒）。 */
    public static final long CLOCK_SKEW_MILLIS = 30_000L;

    @Bean
    public Clock systemClock() {
        return Clock.systemUTC();
    }

    @Bean
    public SessionRegistry sessionRegistry(
            Clock clock,
            @Value("${governance.session.max-active-per-subject:5}") int maxActivePerSubject) {
        return new SessionRegistry(maxActivePerSubject, clock);
    }

    @Bean
    public TokenService tokenService(
            Clock clock, SessionRegistry sessionRegistry,
            @Value("${governance.token.replay-grace-millis:10000}") long replayGraceMillis) {
        return new TokenService(ACCESS_TTL_MILLIS, REFRESH_TTL_MILLIS,
                CLOCK_SKEW_MILLIS, replayGraceMillis, sessionRegistry, clock);
    }

    @Bean
    public SessionService sessionService(SessionRegistry sessionRegistry,
                                         TokenService tokenService) {
        return new SessionService(sessionRegistry, tokenService);
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

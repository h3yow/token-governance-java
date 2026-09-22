package com.github.h3yow.tokengovernancejava.config;

import com.github.h3yow.tokengovernancejava.credential.CredentialService;
import com.github.h3yow.tokengovernancejava.credential.InMemoryCredentialService;
import com.github.h3yow.tokengovernancejava.credential.TokenSettings;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;
import java.time.Duration;

/** 凭证组件与时钟装配。 */
@Configuration
public class TokenGovernanceConfig {

    @Bean
    public Clock systemClock() {
        return Clock.systemUTC();
    }

    @Bean
    public TokenSettings tokenSettings() {
        return new TokenSettings(Duration.ofMinutes(10), Duration.ofHours(8), Duration.ofSeconds(30));
    }

    @Bean
    public CredentialService credentialService(TokenSettings settings, Clock clock) {
        return new InMemoryCredentialService(settings, clock);
    }
}

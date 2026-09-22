package com.github.h3yow.tokengovernancejava.config;

import com.github.h3yow.tokengovernancejava.authz.Effect;
import com.github.h3yow.tokengovernancejava.authz.InMemoryPolicyRepository;
import com.github.h3yow.tokengovernancejava.authz.InMemorySubjectDirectory;
import com.github.h3yow.tokengovernancejava.authz.PolicyRule;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;
import java.util.Set;

/**
 * 本地演示种子数据：
 * <ul>
 *   <li>alice：editor 角色，部门=engineering（可读文档）；</li>
 *   <li>bob：viewer 角色，region=restricted（viewer 可读文档但 restricted 区域显式拒绝，冲突时拒绝优先）。</li>
 * </ul>
 */
@Configuration
public class DemoDataSeeder {

    @Bean
    public CommandLineRunner seedDemoData(InMemorySubjectDirectory subjects, InMemoryPolicyRepository policies) {
        return args -> {
            subjects.register("alice", Set.of("editor"), Map.of("department", "engineering"));
            subjects.register("bob", Set.of("viewer"), Map.of("region", "restricted"));

            policies.add(PolicyRule.role("role-editor-read", Effect.ALLOW, "editor",
                    "document:read", "docs/*"));
            policies.add(PolicyRule.role("role-viewer-read", Effect.ALLOW, "viewer",
                    "document:read", "docs/*"));
            policies.add(PolicyRule.attribute("attr-restricted-deny", Effect.DENY,
                    "document:read", "docs/*", "region", "restricted"));
            policies.add(PolicyRule.attribute("attr-confidential-read", Effect.ALLOW,
                    "document:read", "docs/confidential/*", "clearance", "high"));
            policies.add(PolicyRule.attribute("attr-confidential-deny", Effect.DENY,
                    "document:read", "docs/confidential/*", "clearance", "low"));
        };
    }
}

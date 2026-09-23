package com.github.h3yow.tokengovernancejava.config;

import com.github.h3yow.tokengovernancejava.authz.Effect;
import com.github.h3yow.tokengovernancejava.authz.PolicyRepository;
import com.github.h3yow.tokengovernancejava.authz.PolicyRule;
import com.github.h3yow.tokengovernancejava.authz.Subject;
import com.github.h3yow.tokengovernancejava.authz.SubjectDirectory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;
import java.util.Set;

/**
 * 本地演示数据：预置主体（角色+属性）与规则，便于直接用 curl 体验完整流程。
 */
@Configuration
public class DemoDataInitializer {

    @Bean
    public ApplicationRunner seedDemoData(SubjectDirectory subjects, PolicyRepository policies) {
        return args -> {
            // 编辑 + 工程部门；黑名单属性默认 false。
            subjects.put(new Subject("alice", Set.of("editor"),
                    Map.of("department", "engineering", "blacklisted", "false")));
            subjects.put(new Subject("bob", Set.of("viewer"),
                    Map.of("department", "sales", "blacklisted", "false")));

            // editor 且 engineering 部门：允许编辑文档（角色与属性合取）。
            policies.add(new PolicyRule("allow-editor-engineering", "edit", "document",
                    "editor", "department", "engineering", Effect.ALLOW));
            // 任意登录主体：允许查看文档。
            policies.add(new PolicyRule("allow-anyone-view", "view", "document",
                    null, null, null, Effect.ALLOW));
            // 黑名单：显式拒绝查看（演示显式拒绝优先 / 冲突）。
            policies.add(new PolicyRule("deny-blacklisted-view", "view", "document",
                    null, "blacklisted", "true", Effect.DENY));
        };
    }
}

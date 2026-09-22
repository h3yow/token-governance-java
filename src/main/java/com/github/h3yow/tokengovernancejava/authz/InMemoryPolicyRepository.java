package com.github.h3yow.tokengovernancejava.authz;

import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 内存策略仓库。使用 {@link CopyOnWriteArrayList}，
 * 规则变更对后续判定立即可见，且判定遍历时不加锁、无并发修改异常。
 */
@Component
public class InMemoryPolicyRepository implements PolicyRepository {

    private final CopyOnWriteArrayList<PolicyRule> rules = new CopyOnWriteArrayList<>();

    @Override
    public List<PolicyRule> findAll() {
        return List.copyOf(rules);
    }

    @Override
    public void add(PolicyRule rule) {
        rules.add(rule);
    }
}

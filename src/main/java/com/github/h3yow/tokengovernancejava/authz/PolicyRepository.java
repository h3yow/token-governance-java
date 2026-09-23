package com.github.h3yow.tokengovernancejava.authz;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 策略规则仓库（内存）。
 *
 * <p>线程安全。规则可在运行时增删，调整后下一次判定即生效。</p>
 */
public class PolicyRepository {

    private final CopyOnWriteArrayList<PolicyRule> rules = new CopyOnWriteArrayList<>();

    public void add(PolicyRule rule) {
        if (rule == null) {
            throw new IllegalArgumentException("rule 不能为空");
        }
        rules.add(rule);
    }

    /** 返回当前规则的快照视图；遍历时即使规则被增删也不受影响。 */
    public List<PolicyRule> all() {
        return List.copyOf(rules);
    }
}

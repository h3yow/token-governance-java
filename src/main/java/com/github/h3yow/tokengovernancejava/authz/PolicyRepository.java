package com.github.h3yow.tokengovernancejava.authz;

import java.util.List;

/** 策略规则仓库，判定时实时读取全部规则。 */
public interface PolicyRepository {

    List<PolicyRule> findAll();

    void add(PolicyRule rule);
}

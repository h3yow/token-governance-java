package com.github.h3yow.tokengovernancejava.authz;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 主体实时状态目录。
 *
 * <p>线程安全。授权判定时即时读取，吊销/权限调整后下一次判定即生效，
 * 角色与属性不会被缓存进凭证。</p>
 */
public class SubjectDirectory {

    private final Map<String, Subject> subjects = new ConcurrentHashMap<>();

    public void put(Subject subject) {
        if (subject == null) {
            throw new IllegalArgumentException("subject 不能为空");
        }
        subjects.put(subject.id(), subject);
    }

    public Subject find(String id) {
        return subjects.get(id);
    }

    public void remove(String id) {
        subjects.remove(id);
    }

    /** 就地更新主体角色（权限调整即时生效）。主体不存在时抛非法参数异常。 */
    public void updateRoles(String id, Set<String> roles) {
        subjects.compute(id, (key, existing) -> {
            if (existing == null) {
                throw new IllegalArgumentException("主体不存在: " + key);
            }
            return new Subject(existing.id(), Set.copyOf(roles), existing.attributes());
        });
    }

    /** 就地更新主体属性。主体不存在时抛非法参数异常。 */
    public void updateAttributes(String id, Map<String, String> attributes) {
        subjects.compute(id, (key, existing) -> {
            if (existing == null) {
                throw new IllegalArgumentException("主体不存在: " + key);
            }
            return new Subject(existing.id(), existing.roles(), Map.copyOf(attributes));
        });
    }
}

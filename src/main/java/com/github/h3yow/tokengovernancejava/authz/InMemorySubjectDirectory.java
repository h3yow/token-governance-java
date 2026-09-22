package com.github.h3yow.tokengovernancejava.authz;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 内存主体目录。
 *
 * <p>角色/属性的每次调整都使版本号单调 +1；{@link #update} 使用
 * {@link ConcurrentHashMap#compute} 原子完成"读取-变更-递增"，
 * 保证并发调整不会丢更新、版本号不回退。授权判定时实时读取，
 * 因此吊销或权限调整对后续访问立即生效。</p>
 */
@Component
public class InMemorySubjectDirectory implements SubjectDirectory {

    private final ConcurrentHashMap<String, Subject> store = new ConcurrentHashMap<>();

    @Override
    public Subject register(String id, Set<String> roles, Map<String, String> attributes) {
        Subject subject = new Subject(id, Set.copyOf(roles), Map.copyOf(attributes), 0L);
        Subject previous = store.putIfAbsent(id, subject);
        return previous != null ? previous : subject;
    }

    @Override
    public Subject find(String id) {
        return store.get(id);
    }

    @Override
    public Subject update(String id, Set<String> roles, Map<String, String> attributes) {
        return store.compute(id, (key, current) -> {
            if (current == null) {
                throw new IllegalArgumentException("subject not found: " + id);
            }
            return new Subject(key, Set.copyOf(roles), Map.copyOf(attributes), current.version() + 1);
        });
    }

    @Override
    public void remove(String id) {
        store.remove(id);
    }
}

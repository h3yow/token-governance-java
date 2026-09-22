package com.github.h3yow.tokengovernancejava.authz;

/**
 * 主体目录：保存角色/属性的最新状态，并对每次调整单调递增版本号。
 * 授权判定时实时读取，保证权限调整及时生效。
 */
public interface SubjectDirectory {

    /** 注册主体，初始版本为 0。 */
    Subject register(String id, java.util.Set<String> roles, java.util.Map<String, String> attributes);

    /** 读取主体最新状态；不存在返回 null。 */
    Subject find(String id);

    /** 整体替换角色与属性，版本号 +1。 */
    Subject update(String id, java.util.Set<String> roles, java.util.Map<String, String> attributes);

    /** 删除主体。 */
    void remove(String id);
}

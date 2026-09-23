package com.github.h3yow.tokengovernancejava.web;

import com.github.h3yow.tokengovernancejava.authz.SubjectDirectory;
import com.github.h3yow.tokengovernancejava.web.dto.UpdateAttributesRequest;
import com.github.h3yow.tokengovernancejava.web.dto.UpdateRolesRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 主体状态管理：运行时调整角色/属性。
 * 调整后下一次 /api/check 判定即读取最新状态，即时生效。
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final SubjectDirectory subjectDirectory;

    public AdminController(SubjectDirectory subjectDirectory) {
        this.subjectDirectory = subjectDirectory;
    }

    @PostMapping("/roles")
    public Map<String, Object> updateRoles(@RequestBody UpdateRolesRequest request) {
        if (request == null || request.subject() == null || request.roles() == null) {
            throw new IllegalArgumentException("subject 与 roles 均不能为空");
        }
        subjectDirectory.updateRoles(request.subject(), request.roles());
        return Map.of("subject", request.subject(), "roles", request.roles());
    }

    @PostMapping("/attributes")
    public Map<String, Object> updateAttributes(@RequestBody UpdateAttributesRequest request) {
        if (request == null || request.subject() == null || request.attributes() == null) {
            throw new IllegalArgumentException("subject 与 attributes 均不能为空");
        }
        subjectDirectory.updateAttributes(request.subject(), request.attributes());
        return Map.of("subject", request.subject(), "attributes", request.attributes());
    }
}

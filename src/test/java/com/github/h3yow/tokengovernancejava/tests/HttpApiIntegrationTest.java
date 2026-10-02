package com.github.h3yow.tokengovernancejava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 本地 HTTP 接口集成测试：签发、刷新旋转、重放拒绝、吊销、授权判定与可解释依据。
 */
@SpringBootTest
@AutoConfigureMockMvc
class HttpApiIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(HttpApiIntegrationTest.class);

    @Autowired
    private MockMvc mockMvc;

    private final ObjectMapper mapper = new ObjectMapper();

    private String json(Map<String, String> body) throws Exception {
        return mapper.writeValueAsString(body);
    }

    private JsonNode postJson(String path, Map<String, String> body, int expectStatus) throws Exception {
        String resp = mockMvc.perform(post(path)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(body)))
                .andExpect(status().is(expectStatus))
                .andReturn().getResponse().getContentAsString();
        log.info("[HTTP] POST {} req={} => status={} resp={}", path, body, expectStatus, resp);
        return mapper.readTree(resp);
    }

    @Test
    void issue_refresh_replay_revoke_and_check_flow() throws Exception {
        // 1. 签发（carol 未在演示数据中预置，用于验证“主体缺失默认拒绝”）
        JsonNode issued = postJson("/api/tokens", Map.of("subject", "carol"), 200);
        String access = issued.get("accessToken").asText();
        String refresh = issued.get("refreshToken").asText();

        // 2. 刷新旋转成功
        JsonNode rotated = postJson("/api/tokens/refresh",
                Map.of("refreshToken", refresh), 200);
        String newAccess = rotated.get("accessToken").asText();
        String newRefresh = rotated.get("refreshToken").asText();

        // 3. 重放旧 refresh：409 CONFLICT + ALREADY_CONSUMED（可区分原因）
        mockMvc.perform(post("/api/tokens/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("refreshToken", refresh))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("ALREADY_CONSUMED"));

        // 4. 不存在的凭证：404 NOT_FOUND
        mockMvc.perform(post("/api/tokens/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("refreshToken", "ghost"))))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("NOT_FOUND"));

        // 5. 授权判定：carol 未预置主体，应默认拒绝（DENY_SUBJECT_NOT_FOUND）并返回依据
        Map<String, String> checkBody = new LinkedHashMap<>();
        checkBody.put("accessToken", newAccess);
        checkBody.put("action", "edit");
        checkBody.put("resource", "document");
        postJson("/api/check", checkBody, 200);
        // carol 不存在于主体目录，即使存在匹配 action/resource 的规则也不得放行。
        mockMvc.perform(post("/api/check")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(checkBody)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.permitted").value(false))
                .andExpect(jsonPath("$.code").value("DENY_SUBJECT_NOT_FOUND"));

        // 6. 吊销新 refresh（整族），随后新 access 立即失效
        postJson("/api/tokens/revoke", Map.of("token", newRefresh), 200);
        mockMvc.perform(post("/api/check")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(checkBody)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("REVOKED"));
    }

    @Test
    void session_management_flow() throws Exception {
        String user = "session-user-" + System.nanoTime();

        // 1. 带设备标识签发两个会话；响应携带 sessionId
        JsonNode phone = postJson("/api/tokens",
                Map.of("subject", user, "device", "phone"), 200);
        JsonNode tablet = postJson("/api/tokens",
                Map.of("subject", user, "device", "tablet"), 200);
        String phoneSession = phone.get("sessionId").asText();
        String phoneAccess = phone.get("accessToken").asText();
        String tabletAccess = tablet.get("accessToken").asText();

        // 2. 会话清单：两条记录，只含元信息，不含凭证
        String listResp = mockMvc.perform(get("/api/sessions").param("subject", user))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andReturn().getResponse().getContentAsString();
        log.info("[HTTP] GET /api/sessions subject={} => {}", user, listResp);
        org.junit.jupiter.api.Assertions.assertFalse(listResp.contains(phoneAccess),
                "会话清单不得暴露访问凭证");

        // 3. 单独结束 phone 会话：phone 凭证立即失效，tablet 不受影响
        postJson("/api/sessions/end", Map.of("sessionId", phoneSession), 200);
        Map<String, String> checkPhone = new LinkedHashMap<>();
        checkPhone.put("accessToken", phoneAccess);
        checkPhone.put("action", "view");
        checkPhone.put("resource", "document");
        mockMvc.perform(post("/api/check")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(checkPhone)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("REVOKED"));
        mockMvc.perform(post("/api/check")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("accessToken", tabletAccess,
                                "action", "view", "resource", "document"))))
                .andExpect(status().isOk());
        log.info("[HTTP] phone 会话已下线（403 REVOKED），tablet 会话不受影响");

        // 4. 结束不存在的会话：404 SESSION_NOT_FOUND
        mockMvc.perform(post("/api/sessions/end")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("sessionId", "ghost"))))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("SESSION_NOT_FOUND"));

        // 5. 结束该用户全部会话
        mockMvc.perform(post("/api/sessions/end-all")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("subject", user))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ended").value(1));
        mockMvc.perform(get("/api/sessions").param("subject", user))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));
        log.info("[HTTP] 全部会话已下线，清单为空");
    }

    @Test
    void session_limit_returns_409() throws Exception {
        String user = "limit-user-" + System.nanoTime();
        // 默认上限 5：前 5 个成功，第 6 个明确拒绝且不挤掉旧会话
        for (int i = 0; i < 5; i++) {
            postJson("/api/tokens", Map.of("subject", user, "device", "dev-" + i), 200);
        }
        mockMvc.perform(post("/api/tokens")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("subject", user, "device", "dev-5"))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("SESSION_LIMIT_EXCEEDED"));
        mockMvc.perform(get("/api/sessions").param("subject", user))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(5));
        log.info("[HTTP] 会话数上限=5，第 6 个签发被 409 SESSION_LIMIT_EXCEEDED 拒绝，旧会话保留");
    }
}

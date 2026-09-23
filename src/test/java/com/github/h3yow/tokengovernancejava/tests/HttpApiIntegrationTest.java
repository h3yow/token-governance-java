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
}

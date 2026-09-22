package com.github.h3yow.tokengovernancejava.credential;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 基于内存存储的凭证服务实现。
 *
 * <p><b>签名</b>：访问/刷新凭证均为 {@code base64url(payload).base64url(hmac)} 形式，
 * HMAC-SHA256 防篡改；服务重启后旧凭证全部失效（本地演示实现）。</p>
 *
 * <p><b>刷新旋转（一次性语义）</b>：每个刷新凭证对应一个 {@link RefreshEntry}，
 * 消费动作以 CAS 抢占，同一刷新凭证并发使用时只有一个赢家；
 * 失败方得到 {@link CredentialErrorType#REFRESH_TOKEN_CONSUMED}，
 * 同时触发凭证族吊销（重用检测），后续使用得到 {@link CredentialErrorType#SESSION_REVOKED}。</p>
 *
 * <p><b>状态检查顺序（确定且可解释）</b>：会话吊销 → 已消费/未知 → 已过期。
 * 吊销与旋转在同一个凭证族对象锁上原子进行，因此吊销与刷新之间不存在时间窗：
 * 若旋转先发生，新凭证仍属同一会话，吊销立即覆盖；若吊销先发生，刷新被拒绝。</p>
 *
 * <p><b>时钟偏差</b>：过期判定为 {@code now > exp + leeway}，
 * 轻微落后的时钟不会把有效凭证误判为过期。</p>
 */
public class InMemoryCredentialService implements CredentialService {

    private static final Logger log = LoggerFactory.getLogger(InMemoryCredentialService.class);
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64_DEC = Base64.getUrlDecoder();
    private static final String HMAC_ALGO = "HmacSHA256";

    private final TokenSettings settings;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();
    private final byte[] signingKey;

    /** familyId -> 凭证族状态（族对象同时作为旋转/吊销的锁） */
    private final ConcurrentHashMap<String, FamilyEntry> families = new ConcurrentHashMap<>();
    /** refresh jti -> 一次性刷新凭证状态 */
    private final ConcurrentHashMap<String, RefreshEntry> refreshEntries = new ConcurrentHashMap<>();
    /** subjectId -> 该主体的全部凭证族 */
    private final ConcurrentHashMap<String, Map<String, Boolean>> subjectIndex = new ConcurrentHashMap<>();

    public InMemoryCredentialService(TokenSettings settings, Clock clock) {
        this.settings = settings;
        this.clock = clock;
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        this.signingKey = key;
    }

    // ------------------------------------------------------------------ 签发

    @Override
    public TokenPair issue(String subjectId, long stampedVersion) {
        String familyId = newTokenId("fam");
        FamilyEntry family = new FamilyEntry(familyId, subjectId);
        families.put(familyId, family);
        subjectIndex.computeIfAbsent(subjectId, k -> new ConcurrentHashMap<>()).put(familyId, Boolean.TRUE);
        log.info("credential-issue subject={} family={} version={}", subjectId, familyId, stampedVersion);
        return createPair(family, stampedVersion);
    }

    private TokenPair createPair(FamilyEntry family, long version) {
        Instant now = clock.instant();
        Instant accessExp = now.plus(settings.accessTokenTtl());
        Instant refreshExp = now.plus(settings.refreshTokenTtl());

        String accessJti = newTokenId("ata");
        String refreshJti = newTokenId("rft");

        String accessToken = signToken(new TokenClaims("a", family.subjectId, family.id,
                version, accessJti, accessExp.getEpochSecond()));
        String refreshToken = signToken(new TokenClaims("r", family.subjectId, family.id,
                version, refreshJti, refreshExp.getEpochSecond()));

        refreshEntries.put(refreshJti, new RefreshEntry(family, version, refreshExp, new AtomicBoolean(false)));
        return new TokenPair(family.subjectId, family.id, version,
                accessToken, refreshToken, accessExp, refreshExp);
    }

    // ------------------------------------------------------------------ 刷新

    @Override
    public TokenPair refresh(String refreshToken) {
        TokenClaims claims;
        try {
            claims = parseAndVerify(refreshToken);
        } catch (CredentialException e) {
            // 刷新入口：任何无法识别为合法凭证串的输入都归类为"刷新凭证不存在"，
            // 不泄露它是否是一个结构合法但签名错误的访问凭证
            throw reject(CredentialErrorType.REFRESH_TOKEN_NOT_FOUND,
                    "刷新凭证无法识别：" + e.getMessage());
        }
        if (!"r".equals(claims.typ)) {
            throw reject(CredentialErrorType.REFRESH_TOKEN_NOT_FOUND, "该凭证不是刷新凭证");
        }

        FamilyEntry family = families.get(claims.fam);
        if (family == null) {
            throw reject(CredentialErrorType.REFRESH_TOKEN_NOT_FOUND,
                    "刷新凭证所属会话不存在 jti=" + claims.jti);
        }

        synchronized (family) {
            if (family.revoked) {
                throw reject(CredentialErrorType.SESSION_REVOKED,
                        "凭证族已吊销 family=" + family.id);
            }
            RefreshEntry entry = refreshEntries.get(claims.jti);
            if (entry == null || !entry.consumed.compareAndSet(false, true)) {
                // 重用检测：旧刷新凭证再次出现，整个凭证族立即吊销，杜绝越权窗口
                revokeFamilyLocked(family);
                throw reject(CredentialErrorType.REFRESH_TOKEN_CONSUMED,
                        "刷新凭证已被消费（疑似重放），凭证族已吊销 jti=" + claims.jti);
            }
            Instant now = clock.instant();
            if (now.isAfter(entry.expiresAt.plus(settings.clockSkewLeeway()))) {
                throw reject(CredentialErrorType.REFRESH_TOKEN_EXPIRED,
                        "刷新凭证已过期 exp=" + entry.expiresAt + " now=" + now);
            }
            // 旧凭证一次性消费完成，移除；旋转出新凭证对（版本沿用，刷新不抬权）
            refreshEntries.remove(claims.jti);
            TokenPair rotated = createPair(family, entry.version);
            log.info("credential-refresh success subject={} family={} jti={} -> newJti",
                    family.subjectId, family.id, claims.jti);
            return rotated;
        }
    }

    // --------------------------------------------------------------- 解析校验

    @Override
    public AccessCredential introspect(String accessToken) {
        TokenClaims claims;
        try {
            claims = parseAndVerify(accessToken);
        } catch (CredentialException e) {
            log.info("credential-introspect rejected type={} detail={}", e.getErrorType(), e.getMessage());
            throw e;
        }
        if (!"a".equals(claims.typ)) {
            throw reject(CredentialErrorType.ACCESS_TOKEN_MALFORMED, "该凭证不是访问凭证");
        }
        FamilyEntry family = families.get(claims.fam);
        if (family == null) {
            throw reject(CredentialErrorType.ACCESS_TOKEN_REVOKED,
                    "访问凭证所属会话不存在（可能已因重放被清除） jti=" + claims.jti);
        }
        if (family.revoked) {
            throw reject(CredentialErrorType.ACCESS_TOKEN_REVOKED,
                    "访问凭证所属会话已吊销 family=" + family.id);
        }
        Instant now = clock.instant();
        Instant exp = Instant.ofEpochSecond(claims.exp);
        if (now.isAfter(exp.plus(settings.clockSkewLeeway()))) {
            throw reject(CredentialErrorType.ACCESS_TOKEN_EXPIRED,
                    "访问凭证已过期 exp=" + exp + " now=" + now);
        }
        log.info("credential-introspect ok subject={} family={} version={} jti={}",
                claims.sub, claims.fam, claims.ver, claims.jti);
        return new AccessCredential(claims.sub, claims.fam, claims.ver, claims.jti, exp);
    }

    // ------------------------------------------------------------------ 吊销

    @Override
    public void revokeFamily(String familyId) {
        FamilyEntry family = families.get(familyId);
        if (family != null) {
            synchronized (family) {
                revokeFamilyLocked(family);
            }
        }
        log.info("credential-revoke family={}", familyId);
    }

    @Override
    public void revokeAllForSubject(String subjectId) {
        Map<String, Boolean> familyIds = subjectIndex.get(subjectId);
        if (familyIds != null) {
            for (String familyId : familyIds.keySet()) {
                revokeFamily(familyId);
            }
        }
        log.info("credential-revoke-all subject={}", subjectId);
    }

    private void revokeFamilyLocked(FamilyEntry family) {
        family.revoked = true;
        refreshEntries.values().removeIf(e -> e.family == family);
    }

    // ------------------------------------------------------------ 令牌编码/校验

    private String signToken(TokenClaims c) {
        String payload = c.toJson();
        String body = B64.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        String sig = B64.encodeToString(hmac(body));
        return body + "." + sig;
    }

    private TokenClaims parseAndVerify(String token) {
        if (token == null || token.isBlank()) {
            throw reject(CredentialErrorType.ACCESS_TOKEN_MALFORMED, "凭证为空");
        }
        int dot = token.indexOf('.');
        if (dot <= 0 || dot == token.length() - 1) {
            throw reject(CredentialErrorType.ACCESS_TOKEN_MALFORMED, "凭证格式非法");
        }
        String body = token.substring(0, dot);
        String sig = token.substring(dot + 1);
        byte[] expected = hmac(body);
        byte[] provided;
        try {
            provided = B64_DEC.decode(sig);
        } catch (IllegalArgumentException e) {
            throw reject(CredentialErrorType.ACCESS_TOKEN_MALFORMED, "签名编码非法");
        }
        if (!MessageDigest.isEqual(expected, provided)) {
            // 访问/刷新凭证统一在此处兜底，调用方按自身语义归类
            throw new CredentialException(CredentialErrorType.REFRESH_TOKEN_NOT_FOUND,
                    "凭证签名校验失败（可能不是刷新凭证）");
        }
        try {
            String json = new String(B64_DEC.decode(body), StandardCharsets.UTF_8);
            return TokenClaims.fromJson(json);
        } catch (Exception e) {
            throw reject(CredentialErrorType.ACCESS_TOKEN_MALFORMED, "凭证载荷解析失败");
        }
    }

    private byte[] hmac(String body) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(signingKey, HMAC_ALGO));
            return mac.doFinal(body.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC 不可用", e);
        }
    }

    private String newTokenId(String prefix) {
        byte[] b = new byte[16];
        random.nextBytes(b);
        return prefix + "_" + B64.encodeToString(b);
    }

    private CredentialException reject(CredentialErrorType type, String detail) {
        CredentialException ex = new CredentialException(type, detail);
        log.info("credential-reject type={} detail={}", type, detail);
        return ex;
    }

    // ------------------------------------------------------------- 内部数据结构

    private record TokenClaims(String typ, String sub, String fam, long ver, String jti, long exp) {

        String toJson() {
            return "{\"typ\":\"" + typ + "\",\"sub\":\"" + sub + "\",\"fam\":\"" + fam
                    + "\",\"ver\":" + ver + ",\"jti\":\"" + jti + "\",\"exp\":" + exp + "}";
        }

        static TokenClaims fromJson(String json) {
            return new TokenClaims(
                    str(json, "typ"), str(json, "sub"), str(json, "fam"),
                    lng(json, "ver"), str(json, "jti"), lng(json, "exp"));
        }

        private static String str(String json, String key) {
            String k = "\"" + key + "\":\"";
            int s = json.indexOf(k);
            if (s < 0) {
                throw new IllegalArgumentException("缺少字段 " + key);
            }
            s += k.length();
            int e = json.indexOf('"', s);
            return json.substring(s, e);
        }

        private static long lng(String json, String key) {
            String k = "\"" + key + "\":";
            int s = json.indexOf(k);
            if (s < 0) {
                throw new IllegalArgumentException("缺少字段 " + key);
            }
            return Long.parseLong(json.substring(s + k.length(),
                    json.indexOf(',', s) < 0 ? json.indexOf('}', s) : json.indexOf(',', s)));
        }
    }

    private static final class FamilyEntry {
        final String id;
        final String subjectId;
        volatile boolean revoked;

        FamilyEntry(String id, String subjectId) {
            this.id = id;
            this.subjectId = subjectId;
        }
    }

    private record RefreshEntry(FamilyEntry family, long version, Instant expiresAt, AtomicBoolean consumed) {
    }
}

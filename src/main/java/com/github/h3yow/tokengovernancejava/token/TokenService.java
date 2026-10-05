package com.github.h3yow.tokengovernancejava.token;

import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import com.github.h3yow.tokengovernancejava.session.SessionRegistry;
import com.github.h3yow.tokengovernancejava.session.SessionState;

/**
 * 凭证生命周期服务：签发、刷新旋转、校验、吊销。
 *
 * <p>线程安全。并发正确性由三层机制保证：</p>
 * <ol>
 *   <li>刷新凭证状态的 {@code compareAndSet}：同一刷新凭证在并发下最多成功旋转一次，
 *       抢到 ACTIVE -> CONSUMED 的线程才继续，其余线程一律拒绝；</li>
 *   <li>刷新家族级互斥：旋转（登记新成员）与整族吊销互斥，杜绝“吊销刚发生、旋转仍返回
 *       新有效凭证”的短暂越权窗口；</li>
 *   <li>签发与结束互斥：会话登记与凭证登记在同一家族锁临界区内完成，登记后复查会话
 *       状态；若结束操作在登记过程中先生效（当时家族为空、吊销落空），立即补偿吊销并
 *       拒绝签发，杜绝“会话已下线、刚签发的凭证却还能用”。</li>
 * </ol>
 *
 * <p>会话集成：每个刷新家族即一个登录会话（familyId 即 sessionId）。签发时在
 * {@link SessionRegistry} 登记会话（可携带设备/来源标识，受每用户会话数上限约束）；
 * 旋转时更新会话的最近刷新时间与到期时间；整族吊销时同步结束会话。</p>
 *
 * <p>重放检测：一张已被消费的刷新凭证在“并发抢输宽窗口”之后再次被使用，
 * 判定为事后重放（疑似泄露），立即把整族（即整个会话）作废并抛出
 * {@link RejectionReason#REPLAY_DETECTED}；宽窗口内的并发抢输仍报
 * {@link RejectionReason#ALREADY_CONSUMED}，不误伤正常并发。</p>
 *
 * <p>拒绝原因可区分（见 {@link RejectionReason}）：不存在、已消费（并发抢输）、
 * 重放、已过期、已吊销、类型错误。</p>
 */
public class TokenService {

    /** 并发抢输与事后重放的区分窗口：消费后该窗口内的再次使用视为并发抢输。 */
    public static final long DEFAULT_REPLAY_GRACE_MILLIS = 10_000L;

    private final long accessTtlMillis;
    private final long refreshTtlMillis;
    private final long clockSkewMillis;
    private final long replayGraceMillis;
    private final Clock clock;
    private final SessionRegistry sessionRegistry;

    /** tokenId -> 凭证（不可变标识，可变状态在 Token 内以 AtomicReference 持有）。 */
    private final Map<String, Token> tokens = new ConcurrentHashMap<>();

    /** familyId -> 该家族全部成员 tokenId，用于整族吊销。 */
    private final Map<String, ConcurrentHashMap.KeySetView<String, Boolean>> families =
            new ConcurrentHashMap<>();

    /** familyId -> 家族锁，保证同一家族的旋转与吊销互斥。 */
    private final Map<String, Object> familyLocks = new ConcurrentHashMap<>();

    /**
     * 兼容构造：不接入外部会话注册表时使用内部注册表（不限会话数），
     * 重放宽窗口取默认值。已有调用方式不受影响。
     */
    public TokenService(long accessTtlMillis, long refreshTtlMillis,
                        long clockSkewMillis, Clock clock) {
        this(accessTtlMillis, refreshTtlMillis, clockSkewMillis,
                DEFAULT_REPLAY_GRACE_MILLIS,
                new SessionRegistry(Integer.MAX_VALUE, clock), clock);
    }

    public TokenService(long accessTtlMillis, long refreshTtlMillis,
                        long clockSkewMillis, long replayGraceMillis,
                        SessionRegistry sessionRegistry, Clock clock) {
        if (accessTtlMillis <= 0 || refreshTtlMillis <= 0 || clockSkewMillis < 0
                || replayGraceMillis < 0) {
            throw new IllegalArgumentException("TTL 必须为正，时钟偏差与重放窗口不能为负");
        }
        this.accessTtlMillis = accessTtlMillis;
        this.refreshTtlMillis = refreshTtlMillis;
        this.clockSkewMillis = clockSkewMillis;
        this.replayGraceMillis = replayGraceMillis;
        this.sessionRegistry = sessionRegistry;
        this.clock = clock;
    }

    private long now() {
        return clock.millis();
    }

    private Object lockFor(String familyId) {
        return familyLocks.computeIfAbsent(familyId, k -> new Object());
    }

    /** 为主体签发一对全新凭证（新的刷新家族 / 新会话，默认来源标识）。 */
    public TokenPair issue(String subject) {
        return issue(subject, null);
    }

    /**
     * 为主体签发一对全新凭证，并建立对应登录会话。
     *
     * <p>会话登记与凭证登记在同一个家族锁临界区内完成，与整族吊销互斥；
     * 登记后复查会话状态：若结束操作恰在登记过程中生效（当时家族为空、
     * 吊销落空），立即补偿吊销并拒绝本次签发。两种交错下都不会出现
     * “会话已结束、刚签发的凭证却还能用”。</p>
     *
     * @param deviceLabel 设备/来源标识；为空时使用 default（兼容老调用方式）
     * @throws com.github.h3yow.tokengovernancejava.session.SessionException
     *         该用户有效会话数已达上限时明确拒绝
     * @throws TokenException 会话在签发过程中被并发结束时以
     *         {@link RejectionReason#REVOKED} 拒绝，本次签发的凭证一并作废
     */
    public TokenPair issue(String subject, String deviceLabel) {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject 不能为空");
        }
        long ts = now();
        String familyId = UUID.randomUUID().toString();
        Token access = createToken(TokenType.ACCESS, subject, familyId, ts, accessTtlMillis);
        Token refresh = createToken(TokenType.REFRESH, subject, familyId, ts, refreshTtlMillis);
        synchronized (lockFor(familyId)) {
            // 先登记会话（可能因数量上限被拒绝），再登记凭证，避免超发。
            sessionRegistry.create(subject, deviceLabel, familyId, ts, ts + refreshTtlMillis);
            register(familyId, access, refresh);
            // 复查：若并发结束在凭证登记前已生效（当时家族为空、吊销落空），
            // 在这里补偿吊销，保证已结束会话名下绝不存在可用凭证。
            if (sessionRegistry.get(familyId).getState() == SessionState.ENDED) {
                revokeFamilyLocked(familyId);
                throw new TokenException(RejectionReason.REVOKED,
                        "会话在签发过程中已被结束，本次签发的凭证一并作废");
            }
        }
        return new TokenPair(access, refresh);
    }

    /**
     * 使用刷新凭证旋转出一对新凭证。同一刷新凭证并发使用时仅一次成功。
     *
     * <p>已消费凭证在重放宽窗口之后再次出现，判定为事后重放：整个会话
     * （刷新家族）立即作废，包括上一次旋转换出的新凭证。</p>
     *
     * @throws TokenException 拒绝原因见 {@link RejectionReason}
     */
    public TokenPair rotate(String refreshTokenId) {
        Token token = tokens.get(refreshTokenId);
        if (token == null) {
            throw new TokenException(RejectionReason.NOT_FOUND, "刷新凭证不存在");
        }
        if (token.getType() != TokenType.REFRESH) {
            throw new TokenException(RejectionReason.WRONG_TYPE, "该凭证不是刷新凭证");
        }

        Object familyLock = lockFor(token.getFamilyId());
        synchronized (familyLock) {
            TokenState state = token.getState();
            if (state == TokenState.REVOKED) {
                throw new TokenException(RejectionReason.REVOKED, "刷新凭证已被吊销");
            }
            // 关键原子操作：只有一个线程能把 ACTIVE 改成 CONSUMED。
            if (!token.casState(TokenState.ACTIVE, TokenState.CONSUMED)) {
                if (token.getState() == TokenState.REVOKED) {
                    throw new TokenException(RejectionReason.REVOKED, "刷新凭证已被吊销");
                }
                // CONSUMED：区分“并发抢输”与“事后重放”。
                long consumedAt = token.getConsumedAt();
                boolean replayed = consumedAt >= 0
                        && now() - consumedAt > replayGraceMillis;
                if (replayed) {
                    // 疑似泄露：整个会话（家族）作废，含上次旋转换出的新凭证。
                    revokeFamilyLocked(token.getFamilyId());
                    throw new TokenException(RejectionReason.REPLAY_DETECTED,
                            "刷新凭证疑似被重放，所属会话已整体作废");
                }
                throw new TokenException(RejectionReason.ALREADY_CONSUMED,
                        "刷新凭证已被消费，疑似并发使用或重放");
            }
            token.markConsumed(now());

            // 抢到消费权后再判定过期：时钟偏差容忍窗口内仍视为有效，避免轻微偏差误杀。
            if (isExpiredWithSkew(token)) {
                throw new TokenException(RejectionReason.EXPIRED, "刷新凭证已过期");
            }

            long ts = now();
            // 旋转延续同一家族，便于“一次吊销、整链失效”与重放检测。
            String familyId = token.getFamilyId();
            Token access = createToken(TokenType.ACCESS, token.getSubject(), familyId, ts, accessTtlMillis);
            Token refresh = createToken(TokenType.REFRESH, token.getSubject(), familyId, ts, refreshTtlMillis);
            register(familyId, access, refresh);

            // 复查：登记新成员与吊销互斥，若家族已被吊销则新成员一定也被置为 REVOKED，
            // 此时绝不返回有效凭证，避免吊销竞态下的短暂越权。
            if (refresh.getState() == TokenState.REVOKED) {
                throw new TokenException(RejectionReason.REVOKED,
                        "家族已被吊销，旋转出的凭证立即失效");
            }
            // 旋转成功：更新会话的最近刷新时间与到期时间。
            sessionRegistry.recordRotation(familyId, ts, ts + refreshTtlMillis);
            return new TokenPair(access, refresh);
        }
    }

    /**
     * 校验访问凭证（容忍轻微时钟偏差）。
     *
     * <p>判定顺序：不存在 -> 类型 -> 吊销 -> 过期。吊销为硬状态，先于过期判断，
     * 因此即使时钟存在轻微偏差，被吊销凭证也绝不放行，杜绝吊销竞态下的短暂越权。</p>
     *
     * @throws TokenException 拒绝原因见 {@link RejectionReason}
     */
    public AccessValidation validateAccess(String accessTokenId) {
        Token token = tokens.get(accessTokenId);
        if (token == null) {
            throw new TokenException(RejectionReason.NOT_FOUND, "访问凭证不存在");
        }
        if (token.getType() != TokenType.ACCESS) {
            throw new TokenException(RejectionReason.WRONG_TYPE, "该凭证不是访问凭证");
        }
        if (token.getState() == TokenState.REVOKED) {
            throw new TokenException(RejectionReason.REVOKED, "访问凭证已被吊销");
        }
        if (isExpiredWithSkew(token)) {
            throw new TokenException(RejectionReason.EXPIRED, "访问凭证已过期");
        }
        return new AccessValidation(token.getSubject(), token);
    }

    /** 吊销单个刷新凭证及其整个旋转家族（含同族访问凭证）。 */
    public void revokeRefresh(String refreshTokenId) {
        Token token = tokens.get(refreshTokenId);
        if (token == null) {
            throw new TokenException(RejectionReason.NOT_FOUND, "刷新凭证不存在");
        }
        if (token.getType() != TokenType.REFRESH) {
            throw new TokenException(RejectionReason.WRONG_TYPE, "该凭证不是刷新凭证");
        }
        revokeFamily(token.getFamilyId());
    }

    /** 吊销指定访问凭证及其所属家族（含未失效的刷新链与同族凭证）。 */
    public void revokeAccess(String accessTokenId) {
        Token token = tokens.get(accessTokenId);
        if (token == null) {
            throw new TokenException(RejectionReason.NOT_FOUND, "访问凭证不存在");
        }
        if (token.getType() != TokenType.ACCESS) {
            throw new TokenException(RejectionReason.WRONG_TYPE, "该凭证不是访问凭证");
        }
        revokeFamily(token.getFamilyId());
    }

    // ---- 内部实现 ----

    private Token createToken(TokenType type, String subject, String familyId,
                              long issuedAt, long ttlMillis) {
        return new Token(UUID.randomUUID().toString(), type, subject, familyId,
                issuedAt, issuedAt + ttlMillis, TokenState.ACTIVE);
    }

    private void register(String familyId, Token access, Token refresh) {
        tokens.put(access.getId(), access);
        tokens.put(refresh.getId(), refresh);
        families.computeIfAbsent(familyId, k -> ConcurrentHashMap.newKeySet())
                .addAll(List.of(access.getId(), refresh.getId()));
    }

    /** 按家族 id 整族吊销（会话下线入口；familyId 即 sessionId）。 */
    public void revokeFamilyById(String familyId) {
        revokeFamily(familyId);
    }

    /** 整族吊销：与同家族的旋转互斥，保证吊销后不存在仍可用的新凭证。 */
    private void revokeFamily(String familyId) {
        synchronized (lockFor(familyId)) {
            revokeFamilyLocked(familyId);
        }
    }

    /**
     * 整族吊销（调用方须已持有家族锁）：把家族全部成员置为 REVOKED，
     * 并同步结束对应登录会话（幂等）。
     */
    private void revokeFamilyLocked(String familyId) {
        var memberIds = families.get(familyId);
        if (memberIds != null) {
            for (String id : memberIds) {
                Token member = tokens.get(id);
                if (member != null) {
                    member.setState(TokenState.REVOKED);
                }
            }
        }
        sessionRegistry.markEnded(familyId);
    }

    /**
     * 是否过期，容忍 {@code clockSkewMillis} 时钟偏差：
     * 仅当 当前时间 - 偏差窗口 仍晚于或等于到期时间 时才判过期，
     * 避免把在时钟略快的节点上“看似刚过期”的有效凭证误判。
     */
    private boolean isExpiredWithSkew(Token token) {
        return now() - clockSkewMillis >= token.getExpiresAt();
    }
}

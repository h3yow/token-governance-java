package com.github.h3yow.tokengovernancejava.token;

import com.github.h3yow.tokengovernancejava.session.LoginSession;
import com.github.h3yow.tokengovernancejava.session.SessionException;
import com.github.h3yow.tokengovernancejava.session.SessionInfo;
import com.github.h3yow.tokengovernancejava.session.SessionRejectionReason;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 凭证生命周期服务：签发、刷新旋转、校验、吊销，并在其上提供按登录会话（设备）的管理。
 *
 * <p>线程安全。并发正确性由以下机制保证：</p>
 * <ol>
 *   <li>刷新凭证状态的 {@code compareAndSet}：同一刷新凭证在并发下最多成功旋转一次，
 *       抢到 ACTIVE -> CONSUMED 的线程才继续，其余线程一律拒绝；</li>
 *   <li>刷新家族级互斥：旋转（登记新成员）、整族吊销、会话结束互斥，杜绝“会话已结束 /
 *       家族已吊销，旋转却仍返回一对新有效凭证”的短暂越权窗口；</li>
 *   <li>主体级互斥：签发（占用会话名额）与结束该主体全部会话互斥，保证名额统计不出现
 *       并发超发。</li>
 * </ol>
 *
 * <p><b>会话（设备）模型</b>：一次签发创建一个会话，会话标识即该会话刷新家族的
 * {@code familyId}，之后每次旋转延续同一族。老调用 {@link #issue(String)} 不带设备信息，
 * 视为设备标识为 {@link #DEFAULT_DEVICE_LABEL} 的一个普通会话。每个主体可同时存在的
 * 有效会话数有可配置上限，到上限明确拒绝，绝不悄悄挤掉旧会话。</p>
 *
 * <p><b>重放判定</b>：抢输 CAS 的请求区分两类——与赢家真正并发（首用竞争）的，按
 * {@link RejectionReason#ALREADY_CONSUMED} 拒绝；一张早已消费完、旋转已收尾之后才再次
 * 出现的刷新凭证，判定为<b>会话泄露重放</b>，按 {@link RejectionReason#REPLAY_DETECTED}
 * 拒绝并把整个会话（含刚旋转换出的新访问凭证）立即作废。</p>
 *
 * <p>其余拒绝原因可区分（见 {@link RejectionReason}）：不存在、已过期、已吊销、类型错误。</p>
 */
public class TokenService {

    private static final Logger log = LoggerFactory.getLogger(TokenService.class);

    private final long accessTtlMillis;
    private final long refreshTtlMillis;
    private final long clockSkewMillis;
    private final int maxSessionsPerSubject;
    private final Clock clock;

    /** tokenId -> 凭证（不可变标识，可变状态在 Token 内以 AtomicReference 持有）。 */
    private final Map<String, Token> tokens = new ConcurrentHashMap<>();

    /** familyId -> 该家族全部成员 tokenId，用于整族吊销。 */
    private final Map<String, ConcurrentHashMap.KeySetView<String, Boolean>> families =
            new ConcurrentHashMap<>();

    /** familyId -> 家族锁，保证同一家族的旋转、吊销、会话结束互斥。 */
    private final Map<String, Object> familyLocks = new ConcurrentHashMap<>();

    /** sessionId（=familyId） -> 登录会话。 */
    private final Map<String, LoginSession> sessions = new ConcurrentHashMap<>();

    /** subject -> 该主体的会话 id 集合。 */
    private final Map<String, ConcurrentHashMap.KeySetView<String, Boolean>> sessionsBySubject =
            new ConcurrentHashMap<>();

    /** subject -> 主体锁，保证名额统计/占用与“结束全部会话”互斥。 */
    private final Map<String, Object> subjectLocks = new ConcurrentHashMap<>();

    /** 会话单调创建序号，用于同一毫秒内的稳定排序。 */
    private final AtomicLong sessionSeq = new AtomicLong();

    /** 老调用方式不带设备信息时使用的默认设备/来源标识。 */
    public static final String DEFAULT_DEVICE_LABEL = "default";

    /** 每个主体可同时存在的有效会话数的默认上限。 */
    public static final int DEFAULT_MAX_SESSIONS_PER_SUBJECT = 5;

    /**
     * 并发首用竞争的认定宽限窗口（真实时间，与可拨的业务时钟无关）。
     *
     * <p>赢家 CAS 消费刷新凭证后、旋转收尾后的这段时间内到达的重复提交，仍认定为
     * “第一次并发使用抢输”（{@code ALREADY_CONSUMED}，不作废会话）；超过该窗口的
     * 重复出现才确定为事后重放（{@code REPLAY_DETECTED}，作废整个会话）。</p>
     *
     * <p>纯软件层面无法分辨“被调度器暂停的并发请求”与“旋转完成后才发出的重放”，
     * 因此用一个小的真实时间窗口把调度抖动归入并发情形，避免误杀。</p>
     */
    private static final long CONCURRENT_GRACE_NANOS = 500_000_000L;

    public TokenService(long accessTtlMillis, long refreshTtlMillis,
                        long clockSkewMillis, Clock clock) {
        this(accessTtlMillis, refreshTtlMillis, clockSkewMillis,
                DEFAULT_MAX_SESSIONS_PER_SUBJECT, clock);
    }

    public TokenService(long accessTtlMillis, long refreshTtlMillis,
                        long clockSkewMillis, int maxSessionsPerSubject, Clock clock) {
        if (accessTtlMillis <= 0 || refreshTtlMillis <= 0 || clockSkewMillis < 0) {
            throw new IllegalArgumentException("TTL 必须为正，时钟偏差不能为负");
        }
        if (maxSessionsPerSubject <= 0) {
            throw new IllegalArgumentException("每主体会话上限必须为正");
        }
        this.accessTtlMillis = accessTtlMillis;
        this.refreshTtlMillis = refreshTtlMillis;
        this.clockSkewMillis = clockSkewMillis;
        this.maxSessionsPerSubject = maxSessionsPerSubject;
        this.clock = clock;
    }

    private long now() {
        return clock.millis();
    }

    private Object lockFor(String familyId) {
        return familyLocks.computeIfAbsent(familyId, k -> new Object());
    }

    private Object subjectLockFor(String subject) {
        return subjectLocks.computeIfAbsent(subject, k -> new Object());
    }

    /**
     * 老调用方式：不带设备信息，按默认设备会话签发，行为与历史一致。
     */
    public TokenPair issue(String subject) {
        return issue(subject, DEFAULT_DEVICE_LABEL);
    }

    /**
     * 为主体的一个登录会话（设备/来源）签发一对全新凭证（新的刷新家族 = 新的会话）。
     *
     * <p>当该主体当前仍有效的会话数已达 {@code maxSessionsPerSubject} 时，明确拒绝
     * （{@link SessionRejectionReason#SESSION_LIMIT_REACHED}），不会挤掉旧会话。</p>
     */
    public TokenPair issue(String subject, String deviceLabel) {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject 不能为空");
        }
        String label = (deviceLabel == null || deviceLabel.isBlank())
                ? DEFAULT_DEVICE_LABEL : deviceLabel;
        long ts = now();
        String familyId = UUID.randomUUID().toString();

        synchronized (subjectLockFor(subject)) {
            int active = countActiveSessions(subject, ts);
            if (active >= maxSessionsPerSubject) {
                log.info("[签发-拒绝] subject={} device={} 当前有效会话={} 上限={} => SESSION_LIMIT_REACHED",
                        subject, label, active, maxSessionsPerSubject);
                throw new SessionException(SessionRejectionReason.SESSION_LIMIT_REACHED,
                        "会话数量已达上限(" + maxSessionsPerSubject + ")，请先结束其它设备的会话");
            }
            Token access = createToken(TokenType.ACCESS, subject, familyId, ts, accessTtlMillis);
            Token refresh = createToken(TokenType.REFRESH, subject, familyId, ts, refreshTtlMillis);
            synchronized (lockFor(familyId)) {
                register(familyId, access, refresh);
                LoginSession session = new LoginSession(familyId, subject, label,
                        ts, sessionSeq.incrementAndGet(), refresh.getExpiresAt());
                sessions.put(familyId, session);
                sessionsBySubject.computeIfAbsent(subject, k -> ConcurrentHashMap.newKeySet())
                        .add(familyId);
            }
            log.info("[签发] subject={} device={} session={} activeSessions={} access={} refresh={}",
                    subject, label, familyId, active + 1, access.getId(), refresh.getId());
            return new TokenPair(access, refresh);
        }
    }

    /**
     * 使用刷新凭证旋转出一对新凭证。同一刷新凭证并发使用时仅一次成功。
     *
     * @throws TokenException 拒绝原因见 {@link RejectionReason}；事后重放（非并发抢输）时
     *                        为 {@link RejectionReason#REPLAY_DETECTED} 且整个会话被作废
     */
    public TokenPair rotate(String refreshTokenId) {
        Token token = tokens.get(refreshTokenId);
        if (token == null) {
            throw new TokenException(RejectionReason.NOT_FOUND, "刷新凭证不存在");
        }
        if (token.getType() != TokenType.REFRESH) {
            throw new TokenException(RejectionReason.WRONG_TYPE, "该凭证不是刷新凭证");
        }

        // 进入时快照：刷新凭证是否仍有首用机会（旋转尚未收尾）。
        boolean openAtArrival = !token.isRotationClosed();
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
                return rejectConsumed(token, openAtArrival);
            }

            // 抢到消费权后再判定过期：时钟偏差容忍窗口内仍视为有效，避免轻微偏差误杀。
            if (isExpiredWithSkew(token)) {
                token.setRotationClosed(true);
                throw new TokenException(RejectionReason.EXPIRED, "刷新凭证已过期");
            }

            LoginSession session = sessions.get(token.getFamilyId());
            if (session == null || !session.isActive()) {
                // 会话已结束：CAS 抢到也绝不发出新凭证，并把刚消费的刷新凭证置回硬状态。
                token.setState(TokenState.REVOKED);
                token.setRotationClosed(true);
                throw new TokenException(RejectionReason.REVOKED, "所属会话已结束");
            }

            long ts = now();
            // 旋转延续同一家族（即同一会话），便于“结束会话 / 整族吊销，整条链一起失效”
            // 与重放检测。
            String familyId = token.getFamilyId();
            Token access = createToken(TokenType.ACCESS, token.getSubject(), familyId, ts, accessTtlMillis);
            Token refresh = createToken(TokenType.REFRESH, token.getSubject(), familyId, ts, refreshTtlMillis);
            register(familyId, access, refresh);
            session.touch(ts, refresh.getExpiresAt());
            // 旋转收尾：此后旧刷新凭证再出现即视为事后重放（而非并发首用竞争）。
            token.setRotationClosed(true);

            // 复查：登记新成员与吊销/结束会话互斥，若家族已被吊销则新成员一定也被置为
            // REVOKED，此时绝不返回有效凭证。
            if (refresh.getState() == TokenState.REVOKED || !session.isActive()) {
                throw new TokenException(RejectionReason.REVOKED,
                        "会话/家族已被结束，旋转出的凭证立即失效");
            }
            log.info("[旋转] subject={} session={} 旧refresh={} 新access={} 新refresh={}",
                    token.getSubject(), familyId, token.getId(), access.getId(), refresh.getId());
            return new TokenPair(access, refresh);
        }
    }

    /**
     * 抢输 CAS 后的拒绝分流：
     * <ul>
     *   <li>与赢家真正并发的首用竞争（进入时旋转未收尾，或在赢家消费后的并发宽限窗口内
     *       到达）→ {@code ALREADY_CONSUMED}；</li>
     *   <li>旋转早已收尾、超出宽限窗口后再次出现 → 判为会话泄露重放：作废整个会话并返回
     *       {@code REPLAY_DETECTED}。</li>
     * </ul>
     */
    private TokenPair rejectConsumed(Token token, boolean openAtArrival) {
        long sinceConsumedNanos = System.nanoTime() - token.getConsumedAtNanos();
        boolean withinGrace = sinceConsumedNanos <= CONCURRENT_GRACE_NANOS;
        boolean concurrentContender = openAtArrival || withinGrace;
        if (concurrentContender) {
            log.info("[并发刷新] refresh={} 抢输 CAS（进入时未收尾={}，距赢家消费={}ns，宽限={}ns）=> ALREADY_CONSUMED",
                    token.getId(), openAtArrival, sinceConsumedNanos, CONCURRENT_GRACE_NANOS);
            throw new TokenException(RejectionReason.ALREADY_CONSUMED,
                    "刷新凭证已被消费，疑似并发使用");
        }
        log.warn("[重放告警] refresh={} 在旋转收尾并超出并发宽限窗口后再次出现 subject={} session={}（距赢家消费={}ns）=> REPLAY_DETECTED，作废整个会话",
                token.getId(), token.getSubject(), token.getFamilyId(), sinceConsumedNanos);
        // 会话泄露处理：整个会话作废，含刚才那次旋转换出、看似还很新的访问凭证。
        revokeFamily(token.getFamilyId());
        throw new TokenException(RejectionReason.REPLAY_DETECTED,
                "刷新凭证被重放，疑似会话泄露，该会话已整体作废");
    }

    /**
     * 校验访问凭证（容忍轻微时钟偏差）。
     *
     * <p>判定顺序：不存在 -> 类型 -> 吊销 -> 过期。吊销为硬状态，先于过期判断。</p>
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

    // ---- 登录会话（设备）管理 ----

    /**
     * 列出某主体当前仍有效的会话（状态为 ACTIVE 且刷新凭证未过期），按建立时间升序。
     * 仅暴露会话标识与元信息（来源、建立时间、最近刷新、到期），不暴露任何凭证。
     */
    public List<SessionInfo> listSessions(String subject) {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject 不能为空");
        }
        long ts = now();
        var ids = sessionsBySubject.get(subject);
        List<LoginSession> alive = new ArrayList<>();
        if (ids != null) {
            for (String id : ids) {
                LoginSession s = sessions.get(id);
                if (s != null && s.isActive() && s.getExpiresAt() > ts) {
                    alive.add(s);
                }
            }
        }
        // 按建立时间、再按单调创建序号稳定排序（同一毫秒内签发也有确定顺序）。
        alive.sort(Comparator.comparingLong(LoginSession::getCreatedAt)
                .thenComparingLong(LoginSession::getCreationSeq));
        List<SessionInfo> result = alive.stream().map(LoginSession::toInfo).toList();
        log.info("[会话清单] subject={} 有效会话数={} sessionIds={}",
                subject, result.size(), result.stream().map(SessionInfo::sessionId).toList());
        return result;
    }

    /**
     * 结束单个会话。该会话名下已发出的全部凭证（含最近一次旋转刚换出的访问凭证）
     * 立即失效；不影响同一主体的其它会话。
     *
     * @throws SessionException 会话不存在或已结束时 {@link SessionRejectionReason#SESSION_NOT_FOUND}
     */
    public void endSession(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            throw new IllegalArgumentException("sessionId 不能为空");
        }
        LoginSession session = sessions.get(sessionId);
        if (session == null || !session.isActive()) {
            log.info("[结束会话-拒绝] session={} 不存在或已结束 => SESSION_NOT_FOUND", sessionId);
            throw new SessionException(SessionRejectionReason.SESSION_NOT_FOUND,
                    "会话不存在或已结束: " + sessionId);
        }
        // 与同家族的旋转互斥：会话结束后不可能有旋转返回有效新凭证。
        synchronized (lockFor(sessionId)) {
            if (!session.isActive()) {
                throw new SessionException(SessionRejectionReason.SESSION_NOT_FOUND,
                        "会话不存在或已结束: " + sessionId);
            }
            revokeFamily(sessionId);
        }
        log.info("[结束会话] subject={} device={} session={} 名下凭证全部立即失效",
                session.getSubject(), session.getDeviceLabel(), sessionId);
    }

    /**
     * 结束某主体的全部会话，返回实际结束的会话数。互不影响其它主体。
     * 不存在该主体或无有效会话时返回 0（不报错）。
     */
    public int endAllSessions(String subject) {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject 不能为空");
        }
        int ended = 0;
        synchronized (subjectLockFor(subject)) {
            var ids = sessionsBySubject.get(subject);
            if (ids != null) {
                // 先快照当前仍有效的会话，再逐个在各自家族锁内结束，避免长时间持锁。
                List<String> activeIds = new ArrayList<>();
                for (String id : ids) {
                    LoginSession s = sessions.get(id);
                    if (s != null && s.isActive()) {
                        activeIds.add(id);
                    }
                }
                for (String id : activeIds) {
                    LoginSession s = sessions.get(id);
                    if (s == null) {
                        continue;
                    }
                    synchronized (lockFor(id)) {
                        if (s.end()) {
                            revokeMembers(id);
                            ended++;
                        }
                    }
                }
            }
        }
        log.info("[结束全部会话] subject={} 结束会话数={}", subject, ended);
        return ended;
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

    /**
     * 统计主体当前仍有效（ACTIVE 且刷新未过期）的会话数。
     * 已结束 / 已自然到期的会话不再占用名额，调用方必须持有该主体锁。
     */
    private int countActiveSessions(String subject, long ts) {
        var ids = sessionsBySubject.get(subject);
        if (ids == null) {
            return 0;
        }
        int count = 0;
        for (String id : ids) {
            LoginSession s = sessions.get(id);
            if (s != null && s.isActive() && s.getExpiresAt() > ts) {
                count++;
            }
        }
        return count;
    }

    /**
     * 整族吊销并结束对应会话：与同家族的旋转互斥，保证吊销/结束后不存在仍可用的新凭证。
     */
    private void revokeFamily(String familyId) {
        synchronized (lockFor(familyId)) {
            LoginSession session = sessions.get(familyId);
            if (session != null) {
                session.end();
            }
            revokeMembers(familyId);
        }
    }

    /** 将家族内全部成员置为 REVOKED。调用方必须持有该家族锁。 */
    private void revokeMembers(String familyId) {
        var memberIds = families.get(familyId);
        if (memberIds != null) {
            for (String id : memberIds) {
                Token member = tokens.get(id);
                if (member != null) {
                    member.setState(TokenState.REVOKED);
                }
            }
        }
    }

    /**
     * 是否过期，容忍 {@code clockSkewMillis} 时钟偏差：
     * 仅当 当前时间 - 偏差窗口 仍晚于或等于到期时间 时才判过期。
     */
    private boolean isExpiredWithSkew(Token token) {
        return now() - clockSkewMillis >= token.getExpiresAt();
    }
}

package com.github.h3yow.tokengovernancejava.credential;

import java.time.Duration;

/**
 * 凭证生命周期参数：访问凭证/刷新凭证有效期，以及允许的时钟偏差。
 */
public record TokenSettings(
        Duration accessTokenTtl,
        Duration refreshTokenTtl,
        Duration clockSkewLeeway
) {
}

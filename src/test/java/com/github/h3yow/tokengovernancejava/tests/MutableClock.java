package com.github.h3yow.tokengovernancejava.tests;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 测试用可变时钟：可在运行中把时间拨快，用于模拟过期与时钟偏差。
 */
public class MutableClock extends Clock {

    private final AtomicLong millis;

    public MutableClock(long epochMillis) {
        this.millis = new AtomicLong(epochMillis);
    }

    public void setMillis(long epochMillis) {
        millis.set(epochMillis);
    }

    public void advanceMillis(long delta) {
        millis.addAndGet(delta);
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return this;
    }

    @Override
    public Instant instant() {
        return Instant.ofEpochMilli(millis.get());
    }

    @Override
    public long millis() {
        return millis.get();
    }
}

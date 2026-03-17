package com.nn2.docker_audit_api.securityengineer.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class ClickHouseSchemaInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(ClickHouseSchemaInitializer.class);

    private final JdbcTemplate clickHouseJdbcTemplate;

    public ClickHouseSchemaInitializer(@Qualifier("clickHouseJdbcTemplate") JdbcTemplate clickHouseJdbcTemplate) {
        this.clickHouseJdbcTemplate = clickHouseJdbcTemplate;
    }

    @Override
    public void run(String... args) {
        try {
            clickHouseJdbcTemplate.execute("CREATE DATABASE IF NOT EXISTS audit_analytics");

            clickHouseJdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS audit_analytics.healthcheck_events
                (
                    id UUID DEFAULT generateUUIDv4(),
                    checked_at DateTime DEFAULT now(),
                    source String,
                    status String
                )
                ENGINE = MergeTree
                ORDER BY checked_at
                """);

            clickHouseJdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS audit_analytics.violations_log
                (
                    scan_id UInt64,
                    container_id String,
                    container_name String,
                    host_id UInt64,
                    rule_code String,
                    rule_name String,
                    severity String,
                    passed UInt8,
                    recommendation String,
                    fixed UInt8 DEFAULT 0,
                    timestamp DateTime DEFAULT now()
                )
                ENGINE = MergeTree()
                PARTITION BY toYYYYMM(timestamp)
                ORDER BY (timestamp, host_id, container_id, rule_code)
                TTL timestamp + INTERVAL 30 DAY
                """);

            clickHouseJdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS audit_analytics.security_metrics_hourly
                (
                    hour DateTime,
                    host_id UInt64,
                    total_scans UInt32,
                    critical_violations UInt32,
                    high_violations UInt32,
                    medium_violations UInt32,
                    low_violations UInt32,
                    security_score Float32
                )
                ENGINE = SummingMergeTree()
                ORDER BY (hour, host_id)
                """);

            log.info("ClickHouse schema initialized successfully");
        } catch (Exception ex) {
            log.warn("ClickHouse schema initialization skipped: {}", ex.getMessage());
        }
    }
}

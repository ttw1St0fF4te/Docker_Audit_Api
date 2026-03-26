package com.nn2.docker_audit_api.audit.service;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class AuditLogWriter {

    private static final String INSERT_SQL = """
        INSERT INTO audit_change_log (
            table_name,
            operation,
            record_pk,
            changed_by,
            changed_at,
            before_json,
            after_json,
            request_id
        ) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?)
        """;

    private final JdbcTemplate jdbcTemplate;

    public AuditLogWriter(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void write(
            String tableName,
            String operation,
            String recordPk,
            String changedBy,
            String beforeJson,
            String afterJson,
            String requestId) {
        jdbcTemplate.update(
            INSERT_SQL,
            tableName,
            operation,
            recordPk,
            changedBy,
            beforeJson,
            afterJson,
            requestId);
    }
}

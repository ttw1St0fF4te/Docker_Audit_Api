package com.nn2.docker_audit_api.audit.dto;

public record AuditChangeLogItemResponse(
        Long id,
        String tableName,
        String operation,
        String recordPk,
        String changedBy,
        String changedAt,
        String beforeJson,
        String afterJson,
        String requestId) {
}

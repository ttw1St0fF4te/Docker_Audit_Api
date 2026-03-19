package com.nn2.docker_audit_api.securityengineer.dto;

public record AuditScheduleResponse(
        Long id,
        Long hostId,
        String cronExpression,
        boolean active,
        String lastRun,
        String nextRun) {
}

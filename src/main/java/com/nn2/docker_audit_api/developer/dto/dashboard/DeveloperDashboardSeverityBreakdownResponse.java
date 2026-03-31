package com.nn2.docker_audit_api.developer.dto.dashboard;

public record DeveloperDashboardSeverityBreakdownResponse(
        String generatedAt,
        String period,
        String from,
        String to,
        long critical,
        long high,
        long medium,
        long low,
        long totalFailed) {
}

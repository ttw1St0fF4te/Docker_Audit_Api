package com.nn2.docker_audit_api.securityengineer.dto.analytics;

public record AnalyticsOverviewResponse(
        long totalScans,
        long totalChecks,
        long totalFailed,
        long criticalCount,
        long highCount,
        long mediumCount,
        long lowCount,
        double securityScore) {
}

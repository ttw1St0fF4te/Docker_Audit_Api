package com.nn2.docker_audit_api.securityengineer.dto.analytics;

public record TopHostRiskItemResponse(
        Long hostId,
        String hostName,
        long scans,
        long totalFailed,
        long criticalCount,
        long highCount,
        long mediumCount,
        long lowCount,
        double securityScore) {
}

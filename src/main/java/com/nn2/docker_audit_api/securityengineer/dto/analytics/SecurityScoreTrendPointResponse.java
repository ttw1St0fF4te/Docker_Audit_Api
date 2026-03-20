package com.nn2.docker_audit_api.securityengineer.dto.analytics;

public record SecurityScoreTrendPointResponse(
        String bucketStart,
        double securityScore,
        long totalChecks,
        long totalFailed) {
}

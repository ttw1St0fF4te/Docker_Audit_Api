package com.nn2.docker_audit_api.securityengineer.dto.analytics;

public record SeverityTrendPointResponse(
        String bucketStart,
        long critical,
        long high,
        long medium,
        long low,
        long totalFailed) {
}

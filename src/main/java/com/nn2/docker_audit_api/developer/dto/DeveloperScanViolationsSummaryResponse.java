package com.nn2.docker_audit_api.developer.dto;

public record DeveloperScanViolationsSummaryResponse(
        int totalViolations,
        int affectedContainers,
        int criticalCount,
        int highCount,
        int mediumCount,
        int lowCount) {
}

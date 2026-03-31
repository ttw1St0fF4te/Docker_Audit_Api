package com.nn2.docker_audit_api.developer.dto;

public record DeveloperScanMetadataResponse(
        Long scanId,
        Long hostId,
        String status,
        String startedAt,
        String finishedAt,
        int totalContainers,
        int totalViolations,
        int criticalCount,
        int highCount,
        int mediumCount,
        int lowCount) {
}

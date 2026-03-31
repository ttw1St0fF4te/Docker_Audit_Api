package com.nn2.docker_audit_api.developer.dto.dashboard;

public record DeveloperDashboardTopRiskContainerItemResponse(
        Long scanId,
        Long hostId,
        String host,
        String container,
        long failedChecks,
        String maxSeverity) {
}

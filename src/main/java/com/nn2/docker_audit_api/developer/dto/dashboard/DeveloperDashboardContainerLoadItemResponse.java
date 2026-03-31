package com.nn2.docker_audit_api.developer.dto.dashboard;

public record DeveloperDashboardContainerLoadItemResponse(
        Long hostId,
        String host,
        String containerId,
        String container,
        String status,
        double cpuPercent,
        long memoryUsageBytes,
        long memoryLimitBytes,
        double memoryPercent) {
}

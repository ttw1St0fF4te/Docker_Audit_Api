package com.nn2.docker_audit_api.developer.dto.dashboard;

public record DeveloperDashboardHostContainerStateItemResponse(
        Long hostId,
        String host,
        int total,
        int running,
        int exited,
        int restarting,
        int unhealthy,
        String error) {
}

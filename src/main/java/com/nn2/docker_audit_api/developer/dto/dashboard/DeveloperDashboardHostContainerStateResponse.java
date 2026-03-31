package com.nn2.docker_audit_api.developer.dto.dashboard;

import java.util.List;

public record DeveloperDashboardHostContainerStateResponse(
        String generatedAt,
        List<DeveloperDashboardHostContainerStateItemResponse> items) {
}

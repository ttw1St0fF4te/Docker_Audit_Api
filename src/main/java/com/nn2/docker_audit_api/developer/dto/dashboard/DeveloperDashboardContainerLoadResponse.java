package com.nn2.docker_audit_api.developer.dto.dashboard;

import java.util.List;

public record DeveloperDashboardContainerLoadResponse(
        String generatedAt,
        int limit,
        List<DeveloperDashboardContainerLoadItemResponse> items) {
}

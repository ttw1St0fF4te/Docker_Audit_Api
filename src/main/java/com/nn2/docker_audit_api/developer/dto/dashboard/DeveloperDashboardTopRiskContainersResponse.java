package com.nn2.docker_audit_api.developer.dto.dashboard;

import java.util.List;

public record DeveloperDashboardTopRiskContainersResponse(
        String generatedAt,
        Long scanId,
        int limit,
        List<DeveloperDashboardTopRiskContainerItemResponse> items) {
}

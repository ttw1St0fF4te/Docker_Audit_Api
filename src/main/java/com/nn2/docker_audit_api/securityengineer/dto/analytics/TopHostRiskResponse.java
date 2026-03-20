package com.nn2.docker_audit_api.securityengineer.dto.analytics;

import java.util.List;

public record TopHostRiskResponse(
        List<TopHostRiskItemResponse> items,
        String from,
        String to,
        int limit) {
}

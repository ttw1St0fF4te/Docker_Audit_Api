package com.nn2.docker_audit_api.securityengineer.dto.analytics;

import java.util.List;

public record SecurityScoreTrendResponse(
        List<SecurityScoreTrendPointResponse> items,
        String bucket,
        String from,
        String to) {
}

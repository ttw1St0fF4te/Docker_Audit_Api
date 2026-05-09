package com.nn2.docker_audit_api.securityengineer.dto;

import java.util.List;

public record CveAuditStatusesPageResponse(
        List<CveAuditStatusResponse> items,
        long total,
        int page,
        int size) {
}

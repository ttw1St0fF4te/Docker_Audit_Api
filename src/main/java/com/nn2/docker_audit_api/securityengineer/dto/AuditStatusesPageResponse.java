package com.nn2.docker_audit_api.securityengineer.dto;

import java.util.List;

public record AuditStatusesPageResponse(
        List<AuditStatusResponse> items,
        long total,
        int page,
        int size) {
}

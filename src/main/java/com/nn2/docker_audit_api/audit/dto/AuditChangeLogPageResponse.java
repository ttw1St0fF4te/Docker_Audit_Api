package com.nn2.docker_audit_api.audit.dto;

import java.util.List;

public record AuditChangeLogPageResponse(
        List<AuditChangeLogItemResponse> items,
        long total,
        int page,
        int size) {
}

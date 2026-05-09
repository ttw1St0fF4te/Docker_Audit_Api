package com.nn2.docker_audit_api.securityengineer.dto;

import java.util.List;

public record CveSchedulesPageResponse(
        List<CveScheduleResponse> items,
        long total,
        int page,
        int size) {
}

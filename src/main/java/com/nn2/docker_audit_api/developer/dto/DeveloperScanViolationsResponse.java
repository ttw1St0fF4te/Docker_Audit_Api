package com.nn2.docker_audit_api.developer.dto;

import java.util.List;

public record DeveloperScanViolationsResponse(
        Long scanId,
        boolean detailsAvailable,
        int detailsRetentionDays,
        String detailsMessage,
        DeveloperScanMetadataResponse scan,
        DeveloperScanViolationsSummaryResponse summary,
        List<DeveloperViolationItemResponse> violations) {
}

package com.nn2.docker_audit_api.securityengineer.dto;

public record CveViolationSummaryResponse(
        Long scanId,
        Integer passedChecks,
        Integer failedChecks,
        Integer criticalCount,
        Integer highCount,
        Integer mediumCount,
        Integer lowCount,
        Integer unknownCount) {
}

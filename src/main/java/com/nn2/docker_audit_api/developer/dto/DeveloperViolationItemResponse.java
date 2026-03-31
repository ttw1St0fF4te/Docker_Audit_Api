package com.nn2.docker_audit_api.developer.dto;

public record DeveloperViolationItemResponse(
        Long hostId,
        String host,
        String container,
        String ruleCode,
        String ruleTitle,
        String severity,
        String recommendation,
        String timestamp) {
}

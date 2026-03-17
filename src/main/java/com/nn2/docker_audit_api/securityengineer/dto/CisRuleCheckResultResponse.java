package com.nn2.docker_audit_api.securityengineer.dto;

public record CisRuleCheckResultResponse(
        String cisCode,
        String name,
        String severity,
        boolean passed,
        String message,
        String recommendation) {
}

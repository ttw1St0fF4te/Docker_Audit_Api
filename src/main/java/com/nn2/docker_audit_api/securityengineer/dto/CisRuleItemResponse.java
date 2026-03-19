package com.nn2.docker_audit_api.securityengineer.dto;

public record CisRuleItemResponse(
        Long id,
        String cisCode,
        String name,
        String description,
        String severity,
        String recommendation,
        boolean enabled) {
}

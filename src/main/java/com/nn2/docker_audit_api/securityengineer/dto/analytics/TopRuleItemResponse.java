package com.nn2.docker_audit_api.securityengineer.dto.analytics;

public record TopRuleItemResponse(
        String ruleCode,
        String ruleName,
        long failedCount,
        long affectedScans,
        long affectedContainers) {
}

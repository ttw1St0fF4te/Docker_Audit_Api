package com.nn2.docker_audit_api.securityengineer.dto;

import java.util.List;

public record ContainerCisAuditResponse(
        String containerId,
        String containerName,
        String image,
        int passedRules,
        int failedRules,
        List<CisRuleCheckResultResponse> rules) {
}

package com.nn2.docker_audit_api.securityengineer.dto;

import java.util.List;

public record CisRulesPageResponse(
        List<CisRuleItemResponse> items,
        long total,
        int page,
        int size) {
}

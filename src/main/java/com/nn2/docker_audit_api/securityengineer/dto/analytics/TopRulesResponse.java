package com.nn2.docker_audit_api.securityengineer.dto.analytics;

import java.util.List;

public record TopRulesResponse(
        List<TopRuleItemResponse> items,
        String from,
        String to,
        int limit) {
}

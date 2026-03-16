package com.nn2.docker_audit_api.securityengineer.dto;

import java.util.List;

public record RecentAuditsResponse(
		List<AuditStatusResponse> items,
		Long total) {
}

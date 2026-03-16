package com.nn2.docker_audit_api.securityengineer.dto;

public record AuditViolationSummaryResponse(
		Long scanId,
		Integer passedChecks,
		Integer failedChecks,
		Integer criticalCount,
		Integer highCount,
		Integer mediumCount,
		Integer lowCount) {
}

package com.nn2.docker_audit_api.securityengineer.dto;

public record AuditStatusResponse(
		Long scanId,
		Long hostId,
		String status,
		String startedAt,
		String finishedAt,
		Integer totalContainers,
		Integer totalViolations,
		Integer criticalCount,
		Integer highCount,
		Integer mediumCount,
		Integer lowCount) {
}

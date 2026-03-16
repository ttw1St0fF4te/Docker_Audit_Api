package com.nn2.docker_audit_api.securityengineer.dto;

public record AuditRunResponse(
		Long scanId,
		Long hostId,
		String status,
		String startedAt,
		String message) {
}

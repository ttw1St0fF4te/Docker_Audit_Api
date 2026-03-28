package com.nn2.docker_audit_api.auth.dto;

public record RecoveryActionResponse(
		boolean success,
		String message) {
}

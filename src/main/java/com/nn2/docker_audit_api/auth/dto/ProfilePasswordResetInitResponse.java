package com.nn2.docker_audit_api.auth.dto;

public record ProfilePasswordResetInitResponse(
		boolean success,
		String message,
		String redirectPath) {
}

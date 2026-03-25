package com.nn2.docker_audit_api.auth.dto;

public record AuthResponse(
		Long id,
		String username,
		String fullName,
		String role,
		String roleLabel,
		String homePath,
		String authStatus,
		String accessToken,
		String tokenType,
		String expiresAt) {
}
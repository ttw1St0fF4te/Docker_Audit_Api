package com.nn2.docker_audit_api.admin.dto;

public record AdminCreateUserResponse(
		Long id,
		String username,
		String email,
		String role,
		boolean enabled,
		boolean mustChangePassword,
		String message) {
}

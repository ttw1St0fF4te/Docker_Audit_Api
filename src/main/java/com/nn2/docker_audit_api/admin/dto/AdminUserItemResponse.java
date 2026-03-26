package com.nn2.docker_audit_api.admin.dto;

public record AdminUserItemResponse(
		Long id,
		String username,
		String email,
		String firstName,
		String lastName,
		String role,
		boolean enabled,
		boolean deleted,
		boolean mustChangePassword,
		String createdAt,
		String updatedAt) {
}

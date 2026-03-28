package com.nn2.docker_audit_api.auth.dto;

public record ProfileResponse(
		Long id,
		String username,
		String firstName,
		String lastName,
		String email,
		String role,
		String roleLabel) {
}

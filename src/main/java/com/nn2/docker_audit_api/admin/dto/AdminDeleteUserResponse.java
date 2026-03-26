package com.nn2.docker_audit_api.admin.dto;

public record AdminDeleteUserResponse(
		Long id,
		String username,
		boolean hardDeleted,
		String message) {
}

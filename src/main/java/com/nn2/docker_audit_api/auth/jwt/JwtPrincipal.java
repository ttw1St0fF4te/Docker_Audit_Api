package com.nn2.docker_audit_api.auth.jwt;

import com.nn2.docker_audit_api.auth.model.RoleCode;

public record JwtPrincipal(
		Long id,
		String username,
		String fullName,
		RoleCode role) {
}
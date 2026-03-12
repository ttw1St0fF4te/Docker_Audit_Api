package com.nn2.docker_audit_api.auth.dto;

import java.util.List;

public record WorkspaceResponse(
		String role,
		String title,
		String summary,
		List<String> capabilities,
		List<String> nextSteps) {
}
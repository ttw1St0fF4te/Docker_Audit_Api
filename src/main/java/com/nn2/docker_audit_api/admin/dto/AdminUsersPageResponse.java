package com.nn2.docker_audit_api.admin.dto;

import java.util.List;

public record AdminUsersPageResponse(
		List<AdminUserItemResponse> items,
		long total,
		int page,
		int size) {
}

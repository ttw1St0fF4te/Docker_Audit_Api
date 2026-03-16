package com.nn2.docker_audit_api.securityengineer.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

public record AuditRunRequest(
		@NotNull(message = "Host ID is required")
		@Positive(message = "Host ID must be positive")
		Long hostId) {
}

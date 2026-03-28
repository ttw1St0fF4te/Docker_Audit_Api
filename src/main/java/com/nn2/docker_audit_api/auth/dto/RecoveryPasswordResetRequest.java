package com.nn2.docker_audit_api.auth.dto;

import jakarta.validation.constraints.NotBlank;

public record RecoveryPasswordResetRequest(
		@NotBlank(message = "Укажите username или email")
		String identifier) {
}

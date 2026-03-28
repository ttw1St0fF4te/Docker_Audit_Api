package com.nn2.docker_audit_api.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record RecoveryEmailChangeRequestCodeRequest(
		@NotBlank(message = "Укажите текущий email")
		@Email(message = "Некорректный текущий email")
		String oldEmail,
		@NotBlank(message = "Укажите новый email")
		@Email(message = "Некорректный новый email")
		String newEmail) {
}

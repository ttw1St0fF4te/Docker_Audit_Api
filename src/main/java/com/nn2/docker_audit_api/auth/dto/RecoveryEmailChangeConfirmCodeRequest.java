package com.nn2.docker_audit_api.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record RecoveryEmailChangeConfirmCodeRequest(
		@NotBlank(message = "Укажите текущий email")
		@Email(message = "Некорректный текущий email")
		String oldEmail,
		@NotBlank(message = "Укажите новый email")
		@Email(message = "Некорректный новый email")
		String newEmail,
		@NotBlank(message = "Укажите код подтверждения")
		@Pattern(regexp = "\\d{6}", message = "Код подтверждения должен содержать 6 цифр")
		String code) {
}

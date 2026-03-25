package com.nn2.docker_audit_api.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ActivatePasswordRequest(
		@NotBlank(message = "Укажите логин")
		String username,
		@NotBlank(message = "Укажите временный пароль")
		String temporaryPassword,
		@NotBlank(message = "Укажите новый пароль")
		@Size(min = 8, max = 128, message = "Новый пароль должен содержать от 8 до 128 символов")
		String newPassword) {
}

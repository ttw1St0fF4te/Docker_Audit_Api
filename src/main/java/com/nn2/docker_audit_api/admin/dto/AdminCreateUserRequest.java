package com.nn2.docker_audit_api.admin.dto;

import com.nn2.docker_audit_api.auth.model.RoleCode;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record AdminCreateUserRequest(
		@NotBlank(message = "Укажите email")
		@Email(message = "Укажите корректный email")
		@Size(max = 160, message = "Email не должен превышать 160 символов")
		String email,
		@NotBlank(message = "Укажите username")
		@Size(min = 3, max = 64, message = "Username должен содержать от 3 до 64 символов")
		String username,
		@NotBlank(message = "Укажите имя")
		@Size(max = 100, message = "Имя не должно превышать 100 символов")
		String firstName,
		@NotBlank(message = "Укажите фамилию")
		@Size(max = 100, message = "Фамилия не должна превышать 100 символов")
		String lastName,
		@NotNull(message = "Укажите роль")
		RoleCode role) {
}

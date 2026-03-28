package com.nn2.docker_audit_api.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

import com.nn2.docker_audit_api.auth.model.RoleCode;

public record RecoveryEmailChangeVerifyIdentityRequest(
		@NotBlank(message = "Укажите username")
		String username,
		@NotBlank(message = "Укажите фамилию")
		String lastName,
		RoleCode role,
		@NotBlank(message = "Укажите новый email")
		@Email(message = "Некорректный новый email")
		String newEmail) {
}

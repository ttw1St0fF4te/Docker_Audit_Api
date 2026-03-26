package com.nn2.docker_audit_api.admin.dto;

import com.nn2.docker_audit_api.auth.model.RoleCode;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record AdminUpdateUserRequest(
		@NotBlank(message = "Укажите username")
		@Size(min = 3, max = 64, message = "Username должен содержать от 3 до 64 символов")
		@Pattern(regexp = "^[A-Za-z0-9._-]+$", message = "Username может содержать только латинские буквы, цифры и символы . _ -")
		String username,
		@NotBlank(message = "Укажите email")
		@Email(message = "Укажите корректный email")
		@Size(max = 160, message = "Email не должен превышать 160 символов")
		String email,
		@NotBlank(message = "Укажите имя")
		@Size(min = 2, max = 100, message = "Имя должно содержать от 2 до 100 символов")
		@Pattern(regexp = "^[A-Za-zА-Яа-яЁё' -]+$", message = "Имя может содержать только буквы, пробел, дефис и апостроф")
		String firstName,
		@NotBlank(message = "Укажите фамилию")
		@Size(min = 2, max = 100, message = "Фамилия должна содержать от 2 до 100 символов")
		@Pattern(regexp = "^[A-Za-zА-Яа-яЁё' -]+$", message = "Фамилия может содержать только буквы, пробел, дефис и апостроф")
		String lastName,
		@NotNull(message = "Укажите роль")
		RoleCode role) {
}

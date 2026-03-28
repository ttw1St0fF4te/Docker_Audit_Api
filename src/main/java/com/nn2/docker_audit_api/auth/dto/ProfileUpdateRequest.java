package com.nn2.docker_audit_api.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record ProfileUpdateRequest(
		@NotBlank(message = "Укажите username")
		@Size(min = 3, max = 64, message = "Username должен содержать от 3 до 64 символов")
		@Pattern(regexp = "^[A-Za-z0-9._-]+$", message = "Username может содержать только латинские буквы, цифры и символы . _ -")
		String username,
		@NotBlank(message = "Укажите имя")
		@Size(min = 2, max = 100, message = "Имя должно содержать от 2 до 100 символов")
		@Pattern(regexp = "^[A-Za-zА-Яа-яЁё' -]+$", message = "Имя может содержать только буквы, пробел, дефис и апостроф")
		String firstName,
		@NotBlank(message = "Укажите фамилию")
		@Size(min = 2, max = 100, message = "Фамилия должна содержать от 2 до 100 символов")
		@Pattern(regexp = "^[A-Za-zА-Яа-яЁё' -]+$", message = "Фамилия может содержать только буквы, пробел, дефис и апостроф")
		String lastName) {
}

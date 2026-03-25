package com.nn2.docker_audit_api.mail.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record MailTestRequest(
		@NotBlank(message = "Укажите email получателя")
		@Email(message = "Укажите корректный email получателя")
		String to,
		@Size(max = 160, message = "Тема письма не должна превышать 160 символов")
		String subject,
		@Size(max = 5000, message = "Текст письма не должен превышать 5000 символов")
		String body) {
}

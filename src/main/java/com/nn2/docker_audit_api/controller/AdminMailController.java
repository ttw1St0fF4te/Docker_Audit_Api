package com.nn2.docker_audit_api.controller;

import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nn2.docker_audit_api.mail.dto.MailTestRequest;
import com.nn2.docker_audit_api.mail.dto.MailTestResponse;
import com.nn2.docker_audit_api.mail.service.EmailSenderService;

import jakarta.validation.Valid;

@Validated
@RestController
@RequestMapping("/api/admin/mail")
public class AdminMailController {

	private static final String DEFAULT_SUBJECT = "NN2 Audit Docker: тестовое письмо";
	private static final String DEFAULT_BODY = "Проверка SMTP-модуля выполнена успешно.";

	private final EmailSenderService emailSenderService;

	public AdminMailController(EmailSenderService emailSenderService) {
		this.emailSenderService = emailSenderService;
	}

	@PostMapping("/test")
	public MailTestResponse sendTestMail(@RequestBody @Valid MailTestRequest request) {
		String subject = request.subject() == null || request.subject().isBlank()
			? DEFAULT_SUBJECT
			: request.subject().trim();
		String body = request.body() == null || request.body().isBlank()
			? DEFAULT_BODY
			: request.body().trim();

		boolean sent = emailSenderService.sendPlainText(request.to().trim(), subject, body);
		if (sent) {
			return new MailTestResponse(true, "Тестовое письмо отправлено");
		}
		return new MailTestResponse(false, "Отправка отключена: app.mail.enabled=false");
	}
}

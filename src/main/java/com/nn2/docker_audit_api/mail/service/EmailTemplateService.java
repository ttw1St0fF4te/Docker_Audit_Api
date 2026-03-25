package com.nn2.docker_audit_api.mail.service;

import org.springframework.stereotype.Service;

@Service
public class EmailTemplateService {

	public String inviteSubject() {
		return "NN2 Docker Audit: данные для первого входа";
	}

	public String inviteBody(String username, String temporaryPassword) {
		return """
			Здравствуйте!
			
			Для вас создана учетная запись в системе NN2 Docker Audit.
			
			Логин: %s
			Временный пароль: %s
			
			При первом входе система попросит сменить временный пароль на ваш собственный.
			""".formatted(username, temporaryPassword);
	}

	public String resetPasswordSubject() {
		return "NN2 Docker Audit: временный пароль для восстановления";
	}

	public String resetPasswordBody(String username, String temporaryPassword) {
		return """
			Здравствуйте!
			
			Для вашей учетной записи запрошено восстановление доступа.
			
			Логин: %s
			Временный пароль: %s
			
			После входа обязательно смените пароль.
			""".formatted(username, temporaryPassword);
	}

	public String emailChangeCodeSubject() {
		return "NN2 Docker Audit: код подтверждения смены email";
	}

	public String emailChangeCodeBody(String code) {
		return """
			Здравствуйте!
			
			Код подтверждения смены email: %s
			
			Если вы не выполняли это действие, проигнорируйте письмо.
			""".formatted(code);
	}

	public String vulnerabilityAlertSubject() {
		return "NN2 Docker Audit: уведомление о найденных уязвимостях";
	}

	public String vulnerabilityAlertBody(String message) {
		return """
			Системное уведомление NN2 Docker Audit:
			
			%s
			""".formatted(message);
	}
}

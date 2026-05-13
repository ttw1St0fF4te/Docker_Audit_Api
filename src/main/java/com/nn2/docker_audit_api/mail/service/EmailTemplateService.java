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

	public String developerVulnerabilitySubject(Long scanId, String severity, String scanType) {
		return "NN2 Docker Audit: обнаружены " + severity + " нарушения в " + scanType + "-скане #" + scanId;
	}

	public String developerVulnerabilityBody(
			Long scanId,
			Long hostId,
			String scanType,
			int critical,
			int high,
			int medium,
			int low,
			int totalViolations,
			Integer totalItems,
			int unknown) {
		StringBuilder sb = new StringBuilder();
		sb.append("""
			Здравствуйте!
			
			В %s-скане #%d обнаружены нарушения безопасности.
			
			Хост ID: %d
			""".formatted(scanType, scanId, hostId));
		
		if ("CVE".equals(scanType)) {
			sb.append("Образов в скане: %d%n".formatted(totalItems == null ? 0 : totalItems));
			sb.append("Всего уязвимостей: %d%n".formatted(totalViolations));
		} else {
			sb.append("Контейнеров в скане: %d%n".formatted(totalItems == null ? 0 : totalItems));
			sb.append("Всего нарушений: %d%n".formatted(totalViolations));
		}
		
		sb.append("""
			
			Разбивка по severity:
			- CRITICAL: %d
			- HIGH: %d
			- MEDIUM: %d
			- LOW: %d
			""".formatted(critical, high, medium, low));
		
		if (unknown > 0) {
			sb.append("- UNKNOWN: %d%n".formatted(unknown));
		}
		
		sb.append("""
			
			Откройте раздел "Уведомления" в веб-интерфейсе для просмотра деталей.
			""");
		
		return sb.toString();
	}
}

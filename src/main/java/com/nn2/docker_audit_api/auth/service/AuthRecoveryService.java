package com.nn2.docker_audit_api.auth.service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.nn2.docker_audit_api.admin.service.AdminUserService;
import com.nn2.docker_audit_api.auth.dto.RecoveryActionResponse;
import com.nn2.docker_audit_api.auth.entity.AppUser;
import com.nn2.docker_audit_api.auth.model.RoleCode;
import com.nn2.docker_audit_api.auth.repository.AppUserRepository;
import com.nn2.docker_audit_api.mail.service.EmailSenderService;
import com.nn2.docker_audit_api.mail.service.EmailTemplateService;

@Service
public class AuthRecoveryService {

	private static final Duration CODE_TTL = Duration.ofMinutes(10);
	private static final int MAX_CONFIRM_ATTEMPTS = 5;
	private static final SecureRandom RANDOM = new SecureRandom();

	private final AppUserRepository appUserRepository;
	private final AdminUserService adminUserService;
	private final EmailSenderService emailSenderService;
	private final EmailTemplateService emailTemplateService;
	private final Map<String, EmailChangeSession> emailChangeSessions = new ConcurrentHashMap<>();

	public AuthRecoveryService(
			AppUserRepository appUserRepository,
			AdminUserService adminUserService,
			EmailSenderService emailSenderService,
			EmailTemplateService emailTemplateService) {
		this.appUserRepository = appUserRepository;
		this.adminUserService = adminUserService;
		this.emailSenderService = emailSenderService;
		this.emailTemplateService = emailTemplateService;
	}

	public RecoveryActionResponse initiatePasswordReset(String rawIdentifier) {
		String identifier = normalizeIdentifier(rawIdentifier);
		adminUserService.initiatePasswordResetByIdentifier(identifier);
		return new RecoveryActionResponse(
			true,
			"Если учетная запись существует, временный пароль отправлен на привязанный email");
	}

	public RecoveryActionResponse requestEmailChangeCode(String rawOldEmail, String rawNewEmail) {
		String oldEmail = normalizeEmail(rawOldEmail);
		String newEmail = normalizeEmail(rawNewEmail);

		if (oldEmail.equals(newEmail)) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Новый email должен отличаться от текущего");
		}

		if (appUserRepository.existsByEmail(newEmail)) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, "Новый email уже используется в системе");
		}

		AppUser user = appUserRepository.findByEmail(oldEmail)
			.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Пользователь с указанным email не найден"));

		if (user.isDeleted()) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Операция недоступна для удаленного пользователя");
		}

		String code = generateCode();
		emailChangeSessions.put(oldEmail, new EmailChangeSession(user.getId(), newEmail, code, Instant.now().plus(CODE_TTL), 0));

		emailSenderService.sendPlainText(
			oldEmail,
			emailTemplateService.emailChangeCodeSubject(),
			emailTemplateService.emailChangeCodeBody(code));

		return new RecoveryActionResponse(true, "Код подтверждения отправлен на текущий email");
	}

	public RecoveryActionResponse confirmEmailChangeByCode(String rawOldEmail, String rawNewEmail, String rawCode) {
		String oldEmail = normalizeEmail(rawOldEmail);
		String newEmail = normalizeEmail(rawNewEmail);
		String code = rawCode == null ? "" : rawCode.trim();

		EmailChangeSession session = emailChangeSessions.get(oldEmail);
		if (session == null) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Сессия подтверждения не найдена. Запросите код повторно");
		}

		if (session.expiresAt().isBefore(Instant.now())) {
			emailChangeSessions.remove(oldEmail);
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Срок действия кода истек. Запросите новый код");
		}

		if (!session.newEmail().equals(newEmail)) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Новый email не совпадает с запросом на подтверждение");
		}

		if (!session.code().equals(code)) {
			int nextAttempts = session.attempts() + 1;
			if (nextAttempts >= MAX_CONFIRM_ATTEMPTS) {
				emailChangeSessions.remove(oldEmail);
				throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Код введен неверно слишком много раз. Запросите новый код");
			}
			emailChangeSessions.put(
				oldEmail,
				new EmailChangeSession(session.userId(), session.newEmail(), session.code(), session.expiresAt(), nextAttempts));
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Неверный код подтверждения");
		}

		AppUser user = appUserRepository.findById(session.userId())
			.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Пользователь не найден"));

		if (user.isDeleted()) {
			emailChangeSessions.remove(oldEmail);
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Операция недоступна для удаленного пользователя");
		}

		appUserRepository.findByEmail(newEmail)
			.filter(existing -> !existing.getId().equals(user.getId()))
			.ifPresent(existing -> {
				throw new ResponseStatusException(HttpStatus.CONFLICT, "Новый email уже используется в системе");
			});

		user.setEmail(newEmail);
		appUserRepository.save(user);
		emailChangeSessions.remove(oldEmail);

		return new RecoveryActionResponse(true, "Email успешно изменен");
	}

	public RecoveryActionResponse changeEmailByIdentity(String rawUsername, String rawLastName, RoleCode role, String rawNewEmail) {
		if (role == null) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Укажите роль пользователя");
		}

		String username = normalizeIdentifier(rawUsername);
		String lastName = normalizeLastName(rawLastName);
		String newEmail = normalizeEmail(rawNewEmail);

		if (appUserRepository.existsByEmail(newEmail)) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, "Новый email уже используется в системе");
		}

		AppUser user = appUserRepository.findByUsernameIgnoreCase(username)
			.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Пользователь не найден"));

		if (user.isDeleted()) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Операция недоступна для удаленного пользователя");
		}

		if (!user.getRole().getCode().equals(role) || !equalsIgnoreCaseNormalized(user.getLastName(), lastName)) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Проверочные данные не совпадают");
		}

		if (equalsIgnoreCaseNormalized(user.getEmail(), newEmail)) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Новый email должен отличаться от текущего");
		}

		user.setEmail(newEmail);
		appUserRepository.save(user);

		return new RecoveryActionResponse(true, "Email успешно изменен");
	}

	private String normalizeIdentifier(String rawIdentifier) {
		if (rawIdentifier == null || rawIdentifier.isBlank()) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Укажите username или email");
		}
		return rawIdentifier.trim();
	}

	private String normalizeEmail(String rawEmail) {
		if (rawEmail == null || rawEmail.isBlank()) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email обязателен");
		}
		return rawEmail.trim().toLowerCase(Locale.ROOT);
	}

	private String normalizeLastName(String rawLastName) {
		if (rawLastName == null || rawLastName.isBlank()) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Фамилия обязательна");
		}
		return rawLastName.trim();
	}

	private boolean equalsIgnoreCaseNormalized(String left, String right) {
		if (left == null || right == null) {
			return false;
		}
		return left.trim().equalsIgnoreCase(right.trim());
	}

	private String generateCode() {
		int value = 100000 + RANDOM.nextInt(900000);
		return String.valueOf(value);
	}

	private record EmailChangeSession(Long userId, String newEmail, String code, Instant expiresAt, int attempts) {
	}
}

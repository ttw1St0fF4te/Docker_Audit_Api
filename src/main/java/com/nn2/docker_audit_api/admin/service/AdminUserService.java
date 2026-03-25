package com.nn2.docker_audit_api.admin.service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Locale;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import com.nn2.docker_audit_api.admin.dto.AdminCreateUserRequest;
import com.nn2.docker_audit_api.admin.dto.AdminCreateUserResponse;
import com.nn2.docker_audit_api.auth.entity.AppUser;
import com.nn2.docker_audit_api.auth.model.RoleCode;
import com.nn2.docker_audit_api.auth.repository.AppRoleRepository;
import com.nn2.docker_audit_api.auth.repository.AppUserRepository;
import com.nn2.docker_audit_api.mail.service.EmailSenderService;
import com.nn2.docker_audit_api.mail.service.EmailTemplateService;

@Service
public class AdminUserService {

	private static final String PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";
	private static final int TEMP_PASSWORD_LENGTH = 14;
	private static final SecureRandom RANDOM = new SecureRandom();

	private final AppUserRepository appUserRepository;
	private final AppRoleRepository appRoleRepository;
	private final PasswordEncoder passwordEncoder;
	private final EmailSenderService emailSenderService;
	private final EmailTemplateService emailTemplateService;

	public AdminUserService(
			AppUserRepository appUserRepository,
			AppRoleRepository appRoleRepository,
			PasswordEncoder passwordEncoder,
			EmailSenderService emailSenderService,
			EmailTemplateService emailTemplateService) {
		this.appUserRepository = appUserRepository;
		this.appRoleRepository = appRoleRepository;
		this.passwordEncoder = passwordEncoder;
		this.emailSenderService = emailSenderService;
		this.emailTemplateService = emailTemplateService;
	}

	@Transactional
	public AdminCreateUserResponse createUser(AdminCreateUserRequest request) {
		String normalizedUsername = request.username().trim();
		String normalizedEmail = request.email().trim().toLowerCase(Locale.ROOT);
		String normalizedFirstName = request.firstName().trim();
		String normalizedLastName = request.lastName().trim();
		RoleCode roleCode = request.role();

		if (appUserRepository.existsByUsername(normalizedUsername)) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, "Пользователь с таким username уже существует");
		}
		if (appUserRepository.existsByEmail(normalizedEmail)) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, "Пользователь с таким email уже существует");
		}

		var role = appRoleRepository.findByCode(roleCode)
			.orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Неизвестная роль"));

		String temporaryPassword = generateTemporaryPassword();

		AppUser user = new AppUser();
		user.setUsername(normalizedUsername);
		user.setEmail(normalizedEmail);
		user.setFirstName(normalizedFirstName);
		user.setLastName(normalizedLastName);
		user.setRole(role);
		user.setEnabled(false);
		user.setMustChangePassword(true);
		user.setPasswordChangedAt(null);
		user.setPasswordHash(passwordEncoder.encode(temporaryPassword));

		AppUser saved = appUserRepository.save(user);

		emailSenderService.sendPlainText(
			saved.getEmail(),
			emailTemplateService.inviteSubject(),
			emailTemplateService.inviteBody(saved.getUsername(), temporaryPassword));

		return new AdminCreateUserResponse(
			saved.getId(),
			saved.getUsername(),
			saved.getEmail(),
			saved.getRole().getCode().name(),
			saved.isEnabled(),
			saved.isMustChangePassword(),
			"Пользователь создан. Временный пароль отправлен на email");
	}

	@Transactional
	public AppUser activateTemporaryPassword(String username, String temporaryPassword, String newPassword) {
		AppUser user = appUserRepository.findByUsername(username)
			.orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Неверный логин или пароль"));

		if (!user.isMustChangePassword()) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Для пользователя не требуется смена временного пароля");
		}

		if (!passwordEncoder.matches(temporaryPassword, user.getPasswordHash())) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Неверный логин или пароль");
		}

		if (temporaryPassword.equals(newPassword)) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Новый пароль не должен совпадать с временным");
		}

		validatePasswordComplexity(newPassword);

		user.setPasswordHash(passwordEncoder.encode(newPassword));
		user.setMustChangePassword(false);
		user.setEnabled(true);
		user.setPasswordChangedAt(Instant.now());

		return appUserRepository.save(user);
	}

	private String generateTemporaryPassword() {
		StringBuilder builder = new StringBuilder(TEMP_PASSWORD_LENGTH);
		for (int i = 0; i < TEMP_PASSWORD_LENGTH; i++) {
			int idx = RANDOM.nextInt(PASSWORD_ALPHABET.length());
			builder.append(PASSWORD_ALPHABET.charAt(idx));
		}
		return builder.toString();
	}

	private void validatePasswordComplexity(String password) {
		boolean hasUpper = password.chars().anyMatch(Character::isUpperCase);
		boolean hasLower = password.chars().anyMatch(Character::isLowerCase);
		boolean hasDigit = password.chars().anyMatch(Character::isDigit);
		boolean hasSpecial = password.chars().anyMatch(ch -> !Character.isLetterOrDigit(ch));

		if (!(hasUpper && hasLower && hasDigit && hasSpecial)) {
			throw new ResponseStatusException(
				HttpStatus.BAD_REQUEST,
				"Пароль должен содержать заглавную и строчную буквы, цифру и специальный символ");
		}
	}
}

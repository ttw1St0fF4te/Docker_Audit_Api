package com.nn2.docker_audit_api.admin.service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.Locale;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import com.nn2.docker_audit_api.admin.dto.AdminDeleteUserResponse;
import com.nn2.docker_audit_api.admin.dto.AdminCreateUserRequest;
import com.nn2.docker_audit_api.admin.dto.AdminCreateUserResponse;
import com.nn2.docker_audit_api.admin.dto.AdminUpdateUserRequest;
import com.nn2.docker_audit_api.admin.dto.AdminUserItemResponse;
import com.nn2.docker_audit_api.admin.dto.AdminUsersPageResponse;
import com.nn2.docker_audit_api.auth.entity.AppUser;
import com.nn2.docker_audit_api.auth.model.RoleCode;
import com.nn2.docker_audit_api.auth.repository.AppRoleRepository;
import com.nn2.docker_audit_api.auth.repository.AppUserRepository;
import com.nn2.docker_audit_api.developer.repository.DeveloperNotificationRepository;
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
	private final DeveloperNotificationRepository developerNotificationRepository;

	public AdminUserService(
			AppUserRepository appUserRepository,
			AppRoleRepository appRoleRepository,
			PasswordEncoder passwordEncoder,
			EmailSenderService emailSenderService,
			EmailTemplateService emailTemplateService,
			DeveloperNotificationRepository developerNotificationRepository) {
		this.appUserRepository = appUserRepository;
		this.appRoleRepository = appRoleRepository;
		this.passwordEncoder = passwordEncoder;
		this.emailSenderService = emailSenderService;
		this.emailTemplateService = emailTemplateService;
		this.developerNotificationRepository = developerNotificationRepository;
	}

	public AdminUsersPageResponse listUsers(
			Integer page,
			Integer size,
			String search,
			RoleCode role,
			Boolean enabled,
			Boolean deleted) {
		int safePage = normalizePage(page);
		int safeSize = normalizeSize(size);

		Specification<AppUser> spec = Specification.where(null);

		if (search != null && !search.isBlank()) {
			String normalized = "%" + search.trim().toLowerCase(Locale.ROOT) + "%";
			spec = spec.and((root, query, cb) -> cb.or(
				cb.like(cb.lower(root.get("username")), normalized),
				cb.like(cb.lower(root.get("email")), normalized),
				cb.like(cb.lower(root.get("firstName")), normalized),
				cb.like(cb.lower(root.get("lastName")), normalized)));
		}

		if (role != null) {
			spec = spec.and((root, query, cb) -> cb.equal(root.join("role").get("code"), role));
		}

		if (enabled != null) {
			spec = spec.and((root, query, cb) -> cb.equal(root.get("enabled"), enabled));
		}

		if (deleted != null) {
			spec = spec.and((root, query, cb) -> cb.equal(root.get("deleted"), deleted));
		}

		Pageable pageable = PageRequest.of(safePage, safeSize, Sort.by(Sort.Direction.ASC, "id"));
		Page<AppUser> result = appUserRepository.findAll(spec, pageable);

		List<AdminUserItemResponse> items = result.getContent().stream()
			.map(this::toItem)
			.toList();

		return new AdminUsersPageResponse(items, result.getTotalElements(), safePage, safeSize);
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
		user.setDeleted(false);
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
	public AdminUserItemResponse updateUser(Long userId, AdminUpdateUserRequest request) {
		AppUser user = appUserRepository.findById(userId)
			.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Пользователь не найден"));

		String normalizedUsername = request.username().trim();
		String normalizedEmail = request.email().trim().toLowerCase(Locale.ROOT);

		appUserRepository.findByUsername(normalizedUsername)
			.filter(existing -> !existing.getId().equals(userId))
			.ifPresent(existing -> {
				throw new ResponseStatusException(HttpStatus.CONFLICT, "Пользователь с таким username уже существует");
			});

		appUserRepository.findByEmail(normalizedEmail)
			.filter(existing -> !existing.getId().equals(userId))
			.ifPresent(existing -> {
				throw new ResponseStatusException(HttpStatus.CONFLICT, "Пользователь с таким email уже существует");
			});

		var role = appRoleRepository.findByCode(request.role())
			.orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Неизвестная роль"));

		user.setUsername(normalizedUsername);
		user.setEmail(normalizedEmail);
		user.setFirstName(request.firstName().trim());
		user.setLastName(request.lastName().trim());
		user.setRole(role);

		return toItem(appUserRepository.save(user));
	}

	@Transactional
	public AdminDeleteUserResponse deleteUser(Long userId, boolean hardDelete, Long actorUserId) {
		AppUser user = appUserRepository.findById(userId)
			.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Пользователь не найден"));

		if (user.getId().equals(actorUserId)) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Нельзя удалить самого себя");
		}

		RoleCode roleCode = user.getRole().getCode();

		if (!hardDelete) {
			if (!user.isDeleted()) {
				user.setDeleted(true);
				appUserRepository.save(user);
			}
			return new AdminDeleteUserResponse(user.getId(), user.getUsername(), false, "Пользователь помечен как удаленный");
		}

		if (roleCode != RoleCode.DEVELOPER && roleCode != RoleCode.SUPER_ADMIN) {
			throw new ResponseStatusException(
				HttpStatus.BAD_REQUEST,
				"Физическое удаление доступно только для ролей DEVELOPER и SUPER_ADMIN");
		}

		if (roleCode == RoleCode.DEVELOPER) {
			developerNotificationRepository.deleteAll(
				developerNotificationRepository.findByDeveloperUserIdOrderByCreatedAtDesc(user.getId()));
		}

		appUserRepository.delete(user);
		return new AdminDeleteUserResponse(user.getId(), user.getUsername(), true, "Пользователь удален из системы");
	}

	@Transactional
	public AdminUserItemResponse restoreUser(Long userId) {
		AppUser user = appUserRepository.findById(userId)
			.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Пользователь не найден"));

		if (user.isDeleted()) {
			user.setDeleted(false);
			user = appUserRepository.save(user);
		}

		return toItem(user);
	}

	@Transactional
	public AppUser activateTemporaryPassword(String username, String temporaryPassword, String newPassword) {
		AppUser user = appUserRepository.findByUsername(username)
			.orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Неверный логин или пароль"));

		if (user.isDeleted()) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Неверный логин или пароль");
		}

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

	@Transactional
	public boolean initiatePasswordResetByIdentifier(String identifier) {
		if (identifier == null || identifier.isBlank()) {
			return false;
		}

		String normalized = identifier.trim();
		var optionalUser = appUserRepository.findByUsernameIgnoreCaseOrEmailIgnoreCase(normalized, normalized);
		if (optionalUser.isEmpty()) {
			return false;
		}

		AppUser user = optionalUser.get();
		if (user.isDeleted()) {
			return false;
		}

		applyTemporaryPasswordReset(user);
		return true;
	}

	@Transactional
	public AdminUserItemResponse initiatePasswordResetByUserId(Long userId) {
		AppUser user = appUserRepository.findById(userId)
			.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Пользователь не найден"));

		if (user.isDeleted()) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Нельзя сбросить пароль для удаленного пользователя");
		}

		applyTemporaryPasswordReset(user);
		return toItem(user);
	}

	private void applyTemporaryPasswordReset(AppUser user) {
		String temporaryPassword = generateTemporaryPassword();
		user.setPasswordHash(passwordEncoder.encode(temporaryPassword));
		user.setMustChangePassword(true);
		user.setEnabled(false);
		user.setPasswordChangedAt(null);
		appUserRepository.save(user);

		emailSenderService.sendPlainText(
			user.getEmail(),
			emailTemplateService.resetPasswordSubject(),
			emailTemplateService.resetPasswordBody(user.getUsername(), temporaryPassword));
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

	private AdminUserItemResponse toItem(AppUser user) {
		return new AdminUserItemResponse(
			user.getId(),
			user.getUsername(),
			user.getEmail(),
			user.getFirstName(),
			user.getLastName(),
			user.getRole().getCode().name(),
			user.isEnabled(),
			user.isDeleted(),
			user.isMustChangePassword(),
			toIso(user.getCreatedAt()),
			toIso(user.getUpdatedAt()));
	}

	private String toIso(Instant value) {
		return value == null ? null : value.toString();
	}

	private int normalizePage(Integer page) {
		if (page == null || page < 0) {
			return 0;
		}
		return page;
	}

	private int normalizeSize(Integer size) {
		if (size == null) {
			return 20;
		}
		if (size < 1 || size > 200) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "size должен быть в диапазоне 1..200");
		}
		return size;
	}
}

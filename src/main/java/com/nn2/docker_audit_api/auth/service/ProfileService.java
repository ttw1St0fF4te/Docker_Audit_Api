package com.nn2.docker_audit_api.auth.service;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import com.nn2.docker_audit_api.admin.service.AdminUserService;
import com.nn2.docker_audit_api.auth.dto.ProfilePasswordResetInitResponse;
import com.nn2.docker_audit_api.auth.dto.ProfileResponse;
import com.nn2.docker_audit_api.auth.dto.ProfileUpdateRequest;
import com.nn2.docker_audit_api.auth.entity.AppUser;
import com.nn2.docker_audit_api.auth.jwt.JwtPrincipal;
import com.nn2.docker_audit_api.auth.model.RoleCode;
import com.nn2.docker_audit_api.auth.repository.AppUserRepository;

@Service
public class ProfileService {

	private final AppUserRepository appUserRepository;
	private final AdminUserService adminUserService;

	public ProfileService(AppUserRepository appUserRepository, AdminUserService adminUserService) {
		this.appUserRepository = appUserRepository;
		this.adminUserService = adminUserService;
	}

	@Transactional(readOnly = true)
	public ProfileResponse getProfile(JwtPrincipal principal) {
		AppUser user = requireActiveUser(principal.id());
		return toResponse(user);
	}

	@Transactional
	public ProfileResponse updateProfile(JwtPrincipal principal, ProfileUpdateRequest request) {
		AppUser user = requireActiveUser(principal.id());

		String normalizedUsername = request.username().trim();
		String normalizedFirstName = request.firstName().trim();
		String normalizedLastName = request.lastName().trim();

		appUserRepository.findByUsername(normalizedUsername)
			.filter(existing -> !existing.getId().equals(user.getId()))
			.ifPresent(existing -> {
				throw new ResponseStatusException(HttpStatus.CONFLICT, "Пользователь с таким username уже существует");
			});

		user.setUsername(normalizedUsername);
		user.setFirstName(normalizedFirstName);
		user.setLastName(normalizedLastName);

		return toResponse(appUserRepository.save(user));
	}

	@Transactional
	public ProfilePasswordResetInitResponse initiatePasswordReset(JwtPrincipal principal) {
		AppUser user = requireActiveUser(principal.id());
		adminUserService.initiatePasswordResetByUserId(user.getId());

		return new ProfilePasswordResetInitResponse(
			true,
			"Сброс пароля выполнен. Временный пароль отправлен на ваш email. Перейдите к активации нового пароля.",
			"/activate-password");
	}

	private AppUser requireActiveUser(Long userId) {
		AppUser user = appUserRepository.findById(userId)
			.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Пользователь не найден"));

		if (user.isDeleted()) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Операция недоступна для удаленного пользователя");
		}

		return user;
	}

	private ProfileResponse toResponse(AppUser user) {
		RoleCode role = user.getRole().getCode();
		return new ProfileResponse(
			user.getId(),
			user.getUsername(),
			user.getFirstName(),
			user.getLastName(),
			user.getEmail(),
			role.name(),
			roleLabel(role));
	}

	private String roleLabel(RoleCode role) {
		return switch (role) {
			case SUPER_ADMIN -> "Супер-администратор";
			case SECURITY_ENGINEER -> "Инженер-безопасности";
			case DEVELOPER -> "Разработчик";
		};
	}
}

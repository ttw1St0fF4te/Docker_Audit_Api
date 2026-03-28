package com.nn2.docker_audit_api.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nn2.docker_audit_api.auth.dto.AuthResponse;
import com.nn2.docker_audit_api.auth.dto.ActivatePasswordRequest;
import com.nn2.docker_audit_api.auth.dto.RecoveryActionResponse;
import com.nn2.docker_audit_api.auth.dto.RecoveryEmailChangeConfirmCodeRequest;
import com.nn2.docker_audit_api.auth.dto.RecoveryEmailChangeRequestCodeRequest;
import com.nn2.docker_audit_api.auth.dto.RecoveryEmailChangeVerifyIdentityRequest;
import com.nn2.docker_audit_api.auth.dto.RecoveryPasswordResetRequest;
import com.nn2.docker_audit_api.auth.jwt.JwtPrincipal;
import com.nn2.docker_audit_api.auth.jwt.JwtService;
import com.nn2.docker_audit_api.auth.dto.LoginRequest;
import com.nn2.docker_audit_api.auth.model.RoleCode;
import com.nn2.docker_audit_api.auth.repository.AppUserRepository;
import com.nn2.docker_audit_api.auth.service.AuthRecoveryService;
import com.nn2.docker_audit_api.admin.service.AdminUserService;

import jakarta.validation.Valid;

@Validated
@RestController
@RequestMapping("/api/auth")
public class AuthController {

	private final AppUserRepository appUserRepository;
	private final PasswordEncoder passwordEncoder;
 	private final JwtService jwtService;
	private final AdminUserService adminUserService;
	private final AuthRecoveryService authRecoveryService;

	public AuthController(
			AppUserRepository appUserRepository,
			PasswordEncoder passwordEncoder,
			JwtService jwtService,
			AdminUserService adminUserService,
			AuthRecoveryService authRecoveryService) {
		this.appUserRepository = appUserRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
		this.adminUserService = adminUserService;
		this.authRecoveryService = authRecoveryService;
	}

	@PostMapping("/login")
	public AuthResponse login(@RequestBody @Valid LoginRequest request) {
		String identifier = request.username().trim();
		var user = appUserRepository.findByUsernameIgnoreCaseOrEmailIgnoreCase(identifier, identifier)
			.orElseThrow(() -> invalidCredentials());

		if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
			throw invalidCredentials();
		}

		if (user.isDeleted()) {
			throw invalidCredentials();
		}

		if (user.isMustChangePassword()) {
			JwtPrincipal principal = new JwtPrincipal(user.getId(), user.getUsername(), user.getDisplayName(), user.getRole().getCode());
			return toResponse(principal, null, null, "PASSWORD_CHANGE_REQUIRED", "/activate-password");
		}

		if (!user.isEnabled()) {
			throw invalidCredentials();
		}

		var token = jwtService.createToken(user);
		JwtPrincipal principal = new JwtPrincipal(user.getId(), user.getUsername(), user.getDisplayName(), user.getRole().getCode());
		return toResponse(principal, token.value(), token.expiresAt().toString(), "LOGIN_OK", homePath(principal.role()));
	}

	@PostMapping("/activate-password")
	public AuthResponse activatePassword(@RequestBody @Valid ActivatePasswordRequest request) {
		var user = adminUserService.activateTemporaryPassword(
			request.username().trim(),
			request.temporaryPassword(),
			request.newPassword());

		var token = jwtService.createToken(user);
		JwtPrincipal principal = new JwtPrincipal(user.getId(), user.getUsername(), user.getDisplayName(), user.getRole().getCode());
		return toResponse(principal, token.value(), token.expiresAt().toString(), "LOGIN_OK", homePath(principal.role()));
	}

	@GetMapping("/me")
	public AuthResponse me(Authentication authentication) {
		JwtPrincipal principal = (JwtPrincipal) authentication.getPrincipal();
		return toResponse(principal, null, null, "LOGIN_OK", homePath(principal.role()));
	}

	@PostMapping("/logout")
	public ResponseEntity<Void> logout() {
		return ResponseEntity.noContent().build();
	}

	@PostMapping("/recovery/password/reset")
	public RecoveryActionResponse initiatePasswordReset(@RequestBody @Valid RecoveryPasswordResetRequest request) {
		return authRecoveryService.initiatePasswordReset(request.identifier());
	}

	@PostMapping("/recovery/email/change/request-code")
	public RecoveryActionResponse requestEmailChangeCode(
			@RequestBody @Valid RecoveryEmailChangeRequestCodeRequest request) {
		return authRecoveryService.requestEmailChangeCode(request.oldEmail(), request.newEmail());
	}

	@PostMapping("/recovery/email/change/confirm-code")
	public RecoveryActionResponse confirmEmailChangeCode(
			@RequestBody @Valid RecoveryEmailChangeConfirmCodeRequest request) {
		return authRecoveryService.confirmEmailChangeByCode(request.oldEmail(), request.newEmail(), request.code());
	}

	@PostMapping("/recovery/email/change/verify-identity")
	public RecoveryActionResponse verifyIdentityAndChangeEmail(
			@RequestBody @Valid RecoveryEmailChangeVerifyIdentityRequest request) {
		return authRecoveryService.changeEmailByIdentity(
			request.username(),
			request.lastName(),
			request.role(),
			request.newEmail());
	}

	private AuthResponse toResponse(
			JwtPrincipal principal,
			String accessToken,
			String expiresAt,
			String authStatus,
			String homePath) {
		RoleCode role = principal.role();
		return new AuthResponse(
			principal.id(),
			principal.username(),
			principal.fullName(),
			role.name(),
			roleLabel(role),
			homePath,
			authStatus,
			accessToken,
			accessToken == null ? null : "Bearer",
			expiresAt);
	}

	private String roleLabel(RoleCode role) {
		return switch (role) {
			case SUPER_ADMIN -> "Супер-администратор";
			case SECURITY_ENGINEER -> "Инженер-безопасности";
			case DEVELOPER -> "Разработчик";
		};
	}

	private String homePath(RoleCode role) {
		return switch (role) {
			case SUPER_ADMIN -> "/super-admin";
			case SECURITY_ENGINEER -> "/security-engineer";
			case DEVELOPER -> "/developer";
		};
	}

	private ResponseStatusException invalidCredentials() {
		return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Неверный логин или пароль");
	}
}
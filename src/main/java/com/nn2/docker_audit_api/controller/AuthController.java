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
import com.nn2.docker_audit_api.auth.jwt.JwtPrincipal;
import com.nn2.docker_audit_api.auth.jwt.JwtService;
import com.nn2.docker_audit_api.auth.dto.LoginRequest;
import com.nn2.docker_audit_api.auth.model.RoleCode;
import com.nn2.docker_audit_api.auth.repository.AppUserRepository;

import jakarta.validation.Valid;

@Validated
@RestController
@RequestMapping("/api/auth")
public class AuthController {

	private final AppUserRepository appUserRepository;
	private final PasswordEncoder passwordEncoder;
 	private final JwtService jwtService;

	public AuthController(AppUserRepository appUserRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
		this.appUserRepository = appUserRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
	}

	@PostMapping("/login")
	public AuthResponse login(@RequestBody @Valid LoginRequest request) {
		var user = appUserRepository.findByUsername(request.username())
			.orElseThrow(() -> invalidCredentials());

		if (!user.isEnabled() || !passwordEncoder.matches(request.password(), user.getPasswordHash())) {
			throw invalidCredentials();
		}

		var token = jwtService.createToken(user);
		JwtPrincipal principal = new JwtPrincipal(user.getId(), user.getUsername(), user.getDisplayName(), user.getRole().getCode());
		return toResponse(principal, token.value(), token.expiresAt().toString());
	}

	@GetMapping("/me")
	public AuthResponse me(Authentication authentication) {
		JwtPrincipal principal = (JwtPrincipal) authentication.getPrincipal();
		return toResponse(principal, null, null);
	}

	@PostMapping("/logout")
	public ResponseEntity<Void> logout() {
		return ResponseEntity.noContent().build();
	}

	private AuthResponse toResponse(JwtPrincipal principal, String accessToken, String expiresAt) {
		RoleCode role = principal.role();
		return new AuthResponse(
			principal.id(),
			principal.username(),
			principal.fullName(),
			role.name(),
			roleLabel(role),
			homePath(role),
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
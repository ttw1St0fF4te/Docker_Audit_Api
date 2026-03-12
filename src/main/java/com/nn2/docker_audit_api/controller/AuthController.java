package com.nn2.docker_audit_api.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nn2.docker_audit_api.auth.dto.AuthResponse;
import com.nn2.docker_audit_api.auth.dto.LoginRequest;
import com.nn2.docker_audit_api.auth.model.RoleCode;
import com.nn2.docker_audit_api.auth.repository.AppUserRepository;
import com.nn2.docker_audit_api.auth.security.DatabaseUserDetails;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;

@Validated
@RestController
@RequestMapping("/api/auth")
public class AuthController {

	private final AppUserRepository appUserRepository;
	private final PasswordEncoder passwordEncoder;

	public AuthController(AppUserRepository appUserRepository, PasswordEncoder passwordEncoder) {
		this.appUserRepository = appUserRepository;
		this.passwordEncoder = passwordEncoder;
	}

	@PostMapping("/login")
	public AuthResponse login(@RequestBody @Valid LoginRequest request, HttpServletRequest httpRequest) {
		var user = appUserRepository.findByUsername(request.username())
			.orElseThrow(() -> invalidCredentials());

		if (!user.isEnabled() || !passwordEncoder.matches(request.password(), user.getPasswordHash())) {
			throw invalidCredentials();
		}

		DatabaseUserDetails principal = new DatabaseUserDetails(user);
		Authentication authentication = new UsernamePasswordAuthenticationToken(
			principal,
			null,
			principal.getAuthorities());

		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(authentication);
		SecurityContextHolder.setContext(context);

		HttpSession session = httpRequest.getSession(true);
		session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);

		return toResponse(principal);
	}

	@GetMapping("/me")
	public AuthResponse me(Authentication authentication) {
		return toResponse((DatabaseUserDetails) authentication.getPrincipal());
	}

	@PostMapping("/logout")
	public ResponseEntity<Void> logout(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session != null) {
			session.invalidate();
		}
		SecurityContextHolder.clearContext();
		return ResponseEntity.noContent().build();
	}

	private AuthResponse toResponse(DatabaseUserDetails principal) {
		RoleCode role = principal.getRole();
		return new AuthResponse(
			principal.getId(),
			principal.getUsername(),
			principal.getFullName(),
			role.name(),
			roleLabel(role),
			homePath(role));
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
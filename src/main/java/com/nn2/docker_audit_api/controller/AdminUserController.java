package com.nn2.docker_audit_api.controller;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.nn2.docker_audit_api.admin.dto.AdminDeleteUserResponse;
import com.nn2.docker_audit_api.admin.dto.AdminCreateUserRequest;
import com.nn2.docker_audit_api.admin.dto.AdminCreateUserResponse;
import com.nn2.docker_audit_api.admin.dto.AdminUpdateUserRequest;
import com.nn2.docker_audit_api.admin.dto.AdminUserItemResponse;
import com.nn2.docker_audit_api.admin.dto.AdminUsersPageResponse;
import com.nn2.docker_audit_api.admin.service.AdminUserService;
import com.nn2.docker_audit_api.auth.jwt.JwtPrincipal;
import com.nn2.docker_audit_api.auth.model.RoleCode;

import jakarta.validation.Valid;

@Validated
@RestController
@RequestMapping("/api/admin/users")
public class AdminUserController {

	private final AdminUserService adminUserService;

	public AdminUserController(AdminUserService adminUserService) {
		this.adminUserService = adminUserService;
	}

	@PostMapping
	@ResponseStatus(HttpStatus.CREATED)
	public AdminCreateUserResponse createUser(@RequestBody @Valid AdminCreateUserRequest request) {
		return adminUserService.createUser(request);
	}

	@GetMapping
	public AdminUsersPageResponse listUsers(
			@RequestParam(name = "page", required = false) Integer page,
			@RequestParam(name = "size", required = false) Integer size,
			@RequestParam(name = "search", required = false) String search,
			@RequestParam(name = "role", required = false) RoleCode role,
			@RequestParam(name = "enabled", required = false) Boolean enabled,
			@RequestParam(name = "deleted", required = false) Boolean deleted) {
		return adminUserService.listUsers(page, size, search, role, enabled, deleted);
	}

	@PatchMapping("/{id}")
	public AdminUserItemResponse updateUser(
			@PathVariable("id") Long id,
			@RequestBody @Valid AdminUpdateUserRequest request) {
		return adminUserService.updateUser(id, request);
	}

	@DeleteMapping("/{id}")
	public AdminDeleteUserResponse deleteUser(
			@PathVariable("id") Long id,
			@RequestParam(name = "hard", required = false, defaultValue = "false") boolean hard,
			Authentication authentication) {
		JwtPrincipal principal = (JwtPrincipal) authentication.getPrincipal();
		return adminUserService.deleteUser(id, hard, principal.id());
	}

	@PostMapping("/{id}/restore")
	public AdminUserItemResponse restoreUser(@PathVariable("id") Long id) {
		return adminUserService.restoreUser(id);
	}

	@PostMapping("/{id}/initiate-password-reset")
	public AdminUserItemResponse initiatePasswordReset(@PathVariable("id") Long id) {
		return adminUserService.initiatePasswordResetByUserId(id);
	}
}

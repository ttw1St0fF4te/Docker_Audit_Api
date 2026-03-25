package com.nn2.docker_audit_api.controller;

import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.nn2.docker_audit_api.admin.dto.AdminCreateUserRequest;
import com.nn2.docker_audit_api.admin.dto.AdminCreateUserResponse;
import com.nn2.docker_audit_api.admin.service.AdminUserService;

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
}

package com.nn2.docker_audit_api.controller;

import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nn2.docker_audit_api.auth.dto.ProfilePasswordResetInitResponse;
import com.nn2.docker_audit_api.auth.dto.ProfileResponse;
import com.nn2.docker_audit_api.auth.dto.ProfileUpdateRequest;
import com.nn2.docker_audit_api.auth.jwt.JwtPrincipal;
import com.nn2.docker_audit_api.auth.service.ProfileService;

import jakarta.validation.Valid;

import org.springframework.security.core.Authentication;

@Validated
@RestController
@RequestMapping("/api/profile")
public class ProfileController {

	private final ProfileService profileService;

	public ProfileController(ProfileService profileService) {
		this.profileService = profileService;
	}

	@GetMapping
	public ProfileResponse getProfile(Authentication authentication) {
		JwtPrincipal principal = (JwtPrincipal) authentication.getPrincipal();
		return profileService.getProfile(principal);
	}

	@PatchMapping
	public ProfileResponse updateProfile(
			Authentication authentication,
			@RequestBody @Valid ProfileUpdateRequest request) {
		JwtPrincipal principal = (JwtPrincipal) authentication.getPrincipal();
		return profileService.updateProfile(principal, request);
	}

	@PostMapping("/initiate-password-reset")
	public ProfilePasswordResetInitResponse initiatePasswordReset(Authentication authentication) {
		JwtPrincipal principal = (JwtPrincipal) authentication.getPrincipal();
		return profileService.initiatePasswordReset(principal);
	}
}

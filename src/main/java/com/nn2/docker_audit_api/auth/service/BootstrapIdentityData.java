package com.nn2.docker_audit_api.auth.service;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.nn2.docker_audit_api.auth.entity.AppUser;
import com.nn2.docker_audit_api.auth.model.RoleCode;
import com.nn2.docker_audit_api.auth.repository.AppRoleRepository;
import com.nn2.docker_audit_api.auth.repository.AppUserRepository;

@Component
public class BootstrapIdentityData implements ApplicationRunner {

	private final AppUserRepository appUserRepository;
	private final AppRoleRepository appRoleRepository;
	private final PasswordEncoder passwordEncoder;

	public BootstrapIdentityData(
			AppUserRepository appUserRepository,
			AppRoleRepository appRoleRepository,
			PasswordEncoder passwordEncoder) {
		this.appUserRepository = appUserRepository;
		this.appRoleRepository = appRoleRepository;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	@Transactional
	public void run(ApplicationArguments args) {
		ensureUser("admin", "Супер-администратор", "admin123", RoleCode.SUPER_ADMIN);
		ensureUser("engineer", "Инженер безопасности", "engineer123", RoleCode.SECURITY_ENGINEER);
		ensureUser("developer", "Разработчик", "developer123", RoleCode.DEVELOPER);
	}

	private void ensureUser(String username, String fullName, String rawPassword, RoleCode roleCode) {
		if (appUserRepository.existsByUsername(username)) {
			return;
		}

		var role = appRoleRepository.findByCode(roleCode)
			.orElseThrow(() -> new IllegalStateException("Role not found: " + roleCode));

		AppUser user = new AppUser();
		user.setUsername(username);
		user.setFullName(fullName);
		user.setPasswordHash(passwordEncoder.encode(rawPassword));
		user.setRole(role);
		user.setEnabled(true);

		appUserRepository.save(user);
	}
}
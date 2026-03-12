package com.nn2.docker_audit_api.auth.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.nn2.docker_audit_api.auth.repository.AppUserRepository;
import com.nn2.docker_audit_api.auth.security.DatabaseUserDetails;

@Service
public class DatabaseUserDetailsService implements UserDetailsService {

	private final AppUserRepository appUserRepository;

	public DatabaseUserDetailsService(AppUserRepository appUserRepository) {
		this.appUserRepository = appUserRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return appUserRepository.findByUsername(username)
			.map(DatabaseUserDetails::new)
			.orElseThrow(() -> new UsernameNotFoundException("User not found"));
	}
}
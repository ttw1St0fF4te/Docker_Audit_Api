package com.nn2.docker_audit_api.auth.security;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.nn2.docker_audit_api.auth.entity.AppUser;
import com.nn2.docker_audit_api.auth.model.RoleCode;

public class DatabaseUserDetails implements UserDetails {

	private final Long id;
	private final String username;
	private final String password;
	private final String displayName;
	private final RoleCode role;
	private final boolean enabled;

	public DatabaseUserDetails(AppUser user) {
		this.id = user.getId();
		this.username = user.getUsername();
		this.password = user.getPasswordHash();
		this.displayName = user.getDisplayName();
		this.role = user.getRole().getCode();
		this.enabled = user.isEnabled();
	}

	public Long getId() {
		return id;
	}

	public String getDisplayName() {
		return displayName;
	}

	public String getFullName() {
		return displayName;
	}

	public RoleCode getRole() {
		return role;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return username;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return enabled;
	}
}
package com.nn2.docker_audit_api.auth.entity;

import com.nn2.docker_audit_api.auth.model.RoleCode;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "app_role")
public class AppRole {

	@Id
	private Long id;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, unique = true, length = 64)
	private RoleCode code;

	@Column(name = "display_name", nullable = false, length = 128)
	private String displayName;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public RoleCode getCode() {
		return code;
	}

	public void setCode(RoleCode code) {
		this.code = code;
	}

	public String getDisplayName() {
		return displayName;
	}

	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}
}
package com.nn2.docker_audit_api.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.nn2.docker_audit_api.auth.entity.AppRole;
import com.nn2.docker_audit_api.auth.model.RoleCode;

public interface AppRoleRepository extends JpaRepository<AppRole, Long> {

	Optional<AppRole> findByCode(RoleCode code);
}
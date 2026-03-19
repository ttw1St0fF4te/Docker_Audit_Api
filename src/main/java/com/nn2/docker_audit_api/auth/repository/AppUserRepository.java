package com.nn2.docker_audit_api.auth.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import com.nn2.docker_audit_api.auth.entity.AppUser;
import com.nn2.docker_audit_api.auth.model.RoleCode;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {

	@EntityGraph(attributePaths = "role")
	Optional<AppUser> findByUsername(String username);

	@EntityGraph(attributePaths = "role")
	List<AppUser> findByRoleCodeAndEnabledTrue(RoleCode roleCode);

	boolean existsByUsername(String username);
}
package com.nn2.docker_audit_api.auth.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import com.nn2.docker_audit_api.auth.entity.AppUser;
import com.nn2.docker_audit_api.auth.model.RoleCode;

public interface AppUserRepository extends JpaRepository<AppUser, Long>, JpaSpecificationExecutor<AppUser> {

	@EntityGraph(attributePaths = "role")
	Optional<AppUser> findByUsername(String username);

	@EntityGraph(attributePaths = "role")
	Optional<AppUser> findByUsernameIgnoreCase(String username);

	@EntityGraph(attributePaths = "role")
	Optional<AppUser> findByEmail(String email);

	@EntityGraph(attributePaths = "role")
	Optional<AppUser> findByUsernameIgnoreCaseOrEmailIgnoreCase(String username, String email);

	@EntityGraph(attributePaths = "role")
	List<AppUser> findByRoleCodeAndEnabledTrueAndDeletedFalse(RoleCode roleCode);

	boolean existsByUsername(String username);

	boolean existsByEmail(String email);
}
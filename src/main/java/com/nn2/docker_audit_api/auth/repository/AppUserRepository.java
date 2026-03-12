package com.nn2.docker_audit_api.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import com.nn2.docker_audit_api.auth.entity.AppUser;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {

	@EntityGraph(attributePaths = "role")
	Optional<AppUser> findByUsername(String username);

	boolean existsByUsername(String username);
}
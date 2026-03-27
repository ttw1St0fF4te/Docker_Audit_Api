package com.nn2.docker_audit_api.securityengineer.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.nn2.docker_audit_api.securityengineer.entity.DockerHostEntity;

public interface DockerHostRepository extends JpaRepository<DockerHostEntity, Long> {

    Optional<DockerHostEntity> findByIdAndActiveTrueAndDeletedFalse(Long id);

    Optional<DockerHostEntity> findByBaseUrlIgnoreCase(String baseUrl);

    boolean existsByBaseUrlIgnoreCase(String baseUrl);
}

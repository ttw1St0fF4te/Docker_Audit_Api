package com.nn2.docker_audit_api.securityengineer.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.nn2.docker_audit_api.securityengineer.entity.ScanEntity;

public interface ScanRepository extends JpaRepository<ScanEntity, Long> {

    List<ScanEntity> findTop20ByOrderByStartedAtDesc();

    boolean existsByHostIdAndStatus(Long hostId, String status);
}

package com.nn2.docker_audit_api.securityengineer.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.nn2.docker_audit_api.securityengineer.entity.AuditScheduleEntity;

public interface AuditScheduleRepository extends JpaRepository<AuditScheduleEntity, Long> {

    List<AuditScheduleEntity> findByActiveTrueOrderByIdAsc();

    Optional<AuditScheduleEntity> findFirstByHostIdOrderByIdDesc(Long hostId);
}
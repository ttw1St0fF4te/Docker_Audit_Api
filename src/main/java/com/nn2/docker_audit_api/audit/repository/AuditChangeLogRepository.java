package com.nn2.docker_audit_api.audit.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import com.nn2.docker_audit_api.audit.entity.AuditChangeLogEntity;

public interface AuditChangeLogRepository extends JpaRepository<AuditChangeLogEntity, Long>, JpaSpecificationExecutor<AuditChangeLogEntity> {
}

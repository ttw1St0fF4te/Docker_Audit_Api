package com.nn2.docker_audit_api.audit.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;

import com.nn2.docker_audit_api.audit.entity.AuditChangeLogEntity;

public interface AuditChangeLogRepository extends JpaRepository<AuditChangeLogEntity, Long>, JpaSpecificationExecutor<AuditChangeLogEntity> {

	@Query("select distinct a.tableName from AuditChangeLogEntity a where a.tableName is not null and a.tableName <> '' order by a.tableName asc")
	List<String> findDistinctTableNames();
}

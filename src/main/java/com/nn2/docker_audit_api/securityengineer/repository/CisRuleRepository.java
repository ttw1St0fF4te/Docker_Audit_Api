package com.nn2.docker_audit_api.securityengineer.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.nn2.docker_audit_api.securityengineer.entity.CisRuleEntity;

public interface CisRuleRepository extends JpaRepository<CisRuleEntity, Long> {

    List<CisRuleEntity> findByEnabledTrueOrderByCisCodeAsc();
}

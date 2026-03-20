package com.nn2.docker_audit_api.securityengineer.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.nn2.docker_audit_api.securityengineer.entity.NotificationSettingsEntity;

public interface NotificationSettingsRepository extends JpaRepository<NotificationSettingsEntity, Long> {
}

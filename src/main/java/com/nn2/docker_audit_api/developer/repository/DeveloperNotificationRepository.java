package com.nn2.docker_audit_api.developer.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.nn2.docker_audit_api.developer.entity.DeveloperNotificationEntity;

public interface DeveloperNotificationRepository extends JpaRepository<DeveloperNotificationEntity, Long> {

    List<DeveloperNotificationEntity> findByDeveloperUserIdOrderByCreatedAtDesc(Long developerUserId);

    Optional<DeveloperNotificationEntity> findByIdAndDeveloperUserId(Long id, Long developerUserId);
}

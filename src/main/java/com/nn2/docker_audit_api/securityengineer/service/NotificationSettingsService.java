package com.nn2.docker_audit_api.securityengineer.service;

import java.time.Instant;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.nn2.docker_audit_api.securityengineer.dto.NotificationSettingsResponse;
import com.nn2.docker_audit_api.securityengineer.entity.NotificationSettingsEntity;
import com.nn2.docker_audit_api.securityengineer.model.NotificationSeverityLevel;
import com.nn2.docker_audit_api.securityengineer.repository.NotificationSettingsRepository;

@Service
public class NotificationSettingsService {

    private static final long SETTINGS_SINGLETON_ID = 1L;

    private final NotificationSettingsRepository notificationSettingsRepository;

    public NotificationSettingsService(NotificationSettingsRepository notificationSettingsRepository) {
        this.notificationSettingsRepository = notificationSettingsRepository;
    }

    @Transactional(readOnly = true)
    public NotificationSettingsResponse getSettings() {
        NotificationSettingsEntity entity = getOrCreate();
        return toResponse(entity);
    }

    @Transactional(readOnly = true)
    public NotificationSeverityLevel getThreshold() {
        NotificationSettingsEntity entity = getOrCreate();
        return NotificationSeverityLevel.fromSetting(entity.getMinSeverity());
    }

    @Transactional
    public NotificationSettingsResponse updateSettings(String minSeverityRaw) {
        NotificationSeverityLevel level = NotificationSeverityLevel.fromSetting(minSeverityRaw);

        NotificationSettingsEntity entity = getOrCreate();
        entity.setMinSeverity(level.name());
        entity.setUpdatedAt(Instant.now());

        NotificationSettingsEntity saved = notificationSettingsRepository.save(entity);
        return toResponse(saved);
    }

    private NotificationSettingsEntity getOrCreate() {
        return notificationSettingsRepository.findById(SETTINGS_SINGLETON_ID)
            .orElseGet(() -> {
                NotificationSettingsEntity created = new NotificationSettingsEntity();
                created.setId(SETTINGS_SINGLETON_ID);
                created.setMinSeverity(NotificationSeverityLevel.HIGH.name());
                created.setUpdatedAt(Instant.now());
                return notificationSettingsRepository.save(created);
            });
    }

    private NotificationSettingsResponse toResponse(NotificationSettingsEntity entity) {
        return new NotificationSettingsResponse(
            entity.getMinSeverity(),
            entity.getUpdatedAt() == null ? null : entity.getUpdatedAt().toString());
    }
}

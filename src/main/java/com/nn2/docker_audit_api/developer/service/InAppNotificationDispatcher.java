package com.nn2.docker_audit_api.developer.service;

import java.time.Instant;
import java.util.List;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.nn2.docker_audit_api.auth.entity.AppUser;
import com.nn2.docker_audit_api.auth.model.RoleCode;
import com.nn2.docker_audit_api.auth.repository.AppUserRepository;
import com.nn2.docker_audit_api.developer.entity.DeveloperNotificationEntity;
import com.nn2.docker_audit_api.developer.repository.DeveloperNotificationRepository;
import com.nn2.docker_audit_api.securityengineer.entity.ScanEntity;
import com.nn2.docker_audit_api.securityengineer.model.NotificationSeverityLevel;
import com.nn2.docker_audit_api.securityengineer.service.NotificationSettingsService;

@Component
public class InAppNotificationDispatcher implements NotificationDispatcher {

    private final AppUserRepository appUserRepository;
    private final DeveloperNotificationRepository developerNotificationRepository;
    private final NotificationSettingsService notificationSettingsService;

    public InAppNotificationDispatcher(
            AppUserRepository appUserRepository,
            DeveloperNotificationRepository developerNotificationRepository,
            NotificationSettingsService notificationSettingsService) {
        this.appUserRepository = appUserRepository;
        this.developerNotificationRepository = developerNotificationRepository;
        this.notificationSettingsService = notificationSettingsService;
    }

    @Override
    @Transactional
    public void dispatchForCompletedScan(ScanEntity scan) {
        if (scan == null) {
            return;
        }

        int critical = safe(scan.getCriticalCount());
        int high = safe(scan.getHighCount());
        int medium = safe(scan.getMediumCount());
        int low = safe(scan.getLowCount());

        NotificationSeverityLevel threshold = notificationSettingsService.getThreshold();
        if (!shouldNotify(threshold, critical, high, medium, low)) {
            return;
        }

        String severity = highestPresentSeverity(critical, high, medium, low);
        String title = "Найдены " + severity + " нарушения в скане #" + scan.getId();
        String message = "Скан #" + scan.getId()
            + ": CRITICAL=" + critical
            + ", HIGH=" + high
            + ", MEDIUM=" + medium
            + ", LOW=" + low
            + ". Проверьте детали по отчету сканирования.";

        List<AppUser> developers = appUserRepository.findByRoleCodeAndEnabledTrue(RoleCode.DEVELOPER);
        Instant now = Instant.now();

        List<DeveloperNotificationEntity> notifications = developers.stream()
            .map(user -> buildNotification(user.getId(), scan.getId(), severity, title, message, now))
            .toList();

        if (!notifications.isEmpty()) {
            developerNotificationRepository.saveAll(notifications);
        }
    }

    private DeveloperNotificationEntity buildNotification(
            Long developerUserId,
            Long scanId,
            String severity,
            String title,
            String message,
            Instant createdAt) {
        DeveloperNotificationEntity entity = new DeveloperNotificationEntity();
        entity.setDeveloperUserId(developerUserId);
        entity.setScanId(scanId);
        entity.setSeverity(severity);
        entity.setTitle(title);
        entity.setMessage(message);
        entity.setRead(false);
        entity.setCreatedAt(createdAt);
        entity.setReadAt(null);
        return entity;
    }

    private int safe(Integer value) {
        return value == null ? 0 : value;
    }

    private boolean shouldNotify(NotificationSeverityLevel threshold, int critical, int high, int medium, int low) {
        return (critical > 0 && threshold.includes("CRITICAL"))
            || (high > 0 && threshold.includes("HIGH"))
            || (medium > 0 && threshold.includes("MEDIUM"))
            || (low > 0 && threshold.includes("LOW"));
    }

    private String highestPresentSeverity(int critical, int high, int medium, int low) {
        if (critical > 0) {
            return "CRITICAL";
        }
        if (high > 0) {
            return "HIGH";
        }
        if (medium > 0) {
            return "MEDIUM";
        }
        if (low > 0) {
            return "LOW";
        }
        return "UNKNOWN";
    }
}

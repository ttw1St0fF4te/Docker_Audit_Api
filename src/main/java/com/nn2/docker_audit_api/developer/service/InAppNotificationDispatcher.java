package com.nn2.docker_audit_api.developer.service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.MailException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.nn2.docker_audit_api.auth.entity.AppUser;
import com.nn2.docker_audit_api.auth.model.RoleCode;
import com.nn2.docker_audit_api.auth.repository.AppUserRepository;
import com.nn2.docker_audit_api.developer.entity.DeveloperNotificationEntity;
import com.nn2.docker_audit_api.developer.repository.DeveloperNotificationRepository;
import com.nn2.docker_audit_api.mail.service.EmailSenderService;
import com.nn2.docker_audit_api.mail.service.EmailTemplateService;
import com.nn2.docker_audit_api.securityengineer.entity.CveScanEntity;
import com.nn2.docker_audit_api.securityengineer.entity.ScanEntity;
import com.nn2.docker_audit_api.securityengineer.model.NotificationSeverityLevel;
import com.nn2.docker_audit_api.securityengineer.service.NotificationSettingsService;

@Component
public class InAppNotificationDispatcher implements NotificationDispatcher {

    private static final Logger log = LoggerFactory.getLogger(InAppNotificationDispatcher.class);

    private final AppUserRepository appUserRepository;
    private final DeveloperNotificationRepository developerNotificationRepository;
    private final NotificationSettingsService notificationSettingsService;
    private final EmailSenderService emailSenderService;
    private final EmailTemplateService emailTemplateService;

    public InAppNotificationDispatcher(
            AppUserRepository appUserRepository,
            DeveloperNotificationRepository developerNotificationRepository,
            NotificationSettingsService notificationSettingsService,
            EmailSenderService emailSenderService,
            EmailTemplateService emailTemplateService) {
        this.appUserRepository = appUserRepository;
        this.developerNotificationRepository = developerNotificationRepository;
        this.notificationSettingsService = notificationSettingsService;
        this.emailSenderService = emailSenderService;
        this.emailTemplateService = emailTemplateService;
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
        String title = "Найдены " + severity + " нарушения в CIS-скане #" + scan.getId();
        String message = buildMessage("CIS", scan.getId(), critical, high, medium, low, 0);

        List<AppUser> developers = appUserRepository.findByRoleCodeAndEnabledTrueAndDeletedFalse(RoleCode.DEVELOPER);
        Instant now = Instant.now();

        List<DeveloperNotificationEntity> notifications = developers.stream()
            .map(user -> buildNotification(user.getId(), scan.getId(), "CIS", severity, title, message, now))
            .toList();

        if (!notifications.isEmpty()) {
            developerNotificationRepository.saveAll(notifications);
            sendDeveloperEmails(scan, developers, severity, critical, high, medium, low, 0);
        }
    }

    private void sendDeveloperEmails(
            ScanEntity scan,
            List<AppUser> developers,
            String severity,
            int critical,
            int high,
            int medium,
            int low,
            int unknown) {
        String subject = emailTemplateService.developerVulnerabilitySubject(scan.getId(), severity, "CIS");
        String body = emailTemplateService.developerVulnerabilityBody(
            scan.getId(),
            scan.getHostId(),
            "CIS",
            critical,
            high,
            medium,
            low,
            safe(scan.getTotalViolations()),
            scan.getTotalContainers(),
            unknown);

        sendEmails(scan.getId(), "CIS", developers, subject, body);
    }

    @Override
    @Transactional
    public void dispatchForCompletedCveScan(CveScanEntity scan) {
        if (scan == null) {
            return;
        }

        int critical = safe(scan.getCriticalCount());
        int high = safe(scan.getHighCount());
        int medium = safe(scan.getMediumCount());
        int low = safe(scan.getLowCount());
        int unknown = safe(scan.getUnknownCount());

        NotificationSeverityLevel threshold = notificationSettingsService.getThreshold();
        if (!shouldNotify(threshold, critical, high, medium, low)) {
            return;
        }

        String severity = highestPresentSeverity(critical, high, medium, low);
        String title = "Найдены " + severity + " нарушения в CVE-скане #" + scan.getId();
        String message = buildMessage("CVE", scan.getId(), critical, high, medium, low, unknown);

        List<AppUser> developers = appUserRepository.findByRoleCodeAndEnabledTrueAndDeletedFalse(RoleCode.DEVELOPER);
        Instant now = Instant.now();

        List<DeveloperNotificationEntity> notifications = developers.stream()
            .map(user -> buildNotification(user.getId(), scan.getId(), "CVE", severity, title, message, now))
            .toList();

        if (!notifications.isEmpty()) {
            developerNotificationRepository.saveAll(notifications);
            sendDeveloperCveEmails(scan, developers, severity, critical, high, medium, low, unknown);
        }
    }

    private void sendDeveloperCveEmails(
            CveScanEntity scan,
            List<AppUser> developers,
            String severity,
            int critical,
            int high,
            int medium,
            int low,
            int unknown) {
        String subject = emailTemplateService.developerVulnerabilitySubject(scan.getId(), severity, "CVE");
        String body = emailTemplateService.developerVulnerabilityBody(
            scan.getId(),
            scan.getHostId(),
            "CVE",
            critical,
            high,
            medium,
            low,
            safe(scan.getTotalVulnerabilities()),
            safe(scan.getTotalImages()),
            unknown);

        sendEmails(scan.getId(), "CVE", developers, subject, body);
    }

    private void sendEmails(Long scanId, String scanType, List<AppUser> developers, String subject, String body) {
        int successCount = 0;
        int failedCount = 0;
        List<String> successRecipients = new ArrayList<>();
        List<String> failedRecipients = new ArrayList<>();

        for (AppUser developer : developers) {
            String recipientMeta = "userId=" + developer.getId() + ",email=" + developer.getEmail();
            try {
                boolean sent = emailSenderService.sendPlainText(developer.getEmail(), subject, body);
                if (sent) {
                    successCount++;
                    successRecipients.add(recipientMeta);
                } else {
                    failedCount++;
                    failedRecipients.add(recipientMeta + ",reason=MAIL_DISABLED_OR_SKIPPED");
                    log.warn("Email notification was not sent for {} scan {} to {}", scanType, scanId, recipientMeta);
                }
            } catch (MailException ex) {
                failedCount++;
                failedRecipients.add(recipientMeta + ",reason=" + ex.getClass().getSimpleName());
                log.warn("Email notification failed for {} scan {} to {}", scanType, scanId, recipientMeta, ex);
            } catch (RuntimeException ex) {
                failedCount++;
                failedRecipients.add(recipientMeta + ",reason=" + ex.getClass().getSimpleName());
                log.warn("Unexpected email failure for {} scan {} to {}", scanType, scanId, recipientMeta, ex);
            }
        }

        log.info(
            "Developer email fan-out finished: {} scanId={}, recipients={}, successCount={}, failedCount={}, successRecipients={}, failedRecipients={}",
            scanType,
            scanId,
            developers.size(),
            successCount,
            failedCount,
            successRecipients,
            failedRecipients);
    }

    private String buildMessage(String scanType, Long scanId, int critical, int high, int medium, int low, int unknown) {
        StringBuilder sb = new StringBuilder();
        sb.append(scanType).append("-скан #").append(scanId).append(": ");
        sb.append("CRITICAL=").append(critical);
        sb.append(", HIGH=").append(high);
        sb.append(", MEDIUM=").append(medium);
        sb.append(", LOW=").append(low);
        if (unknown > 0) {
            sb.append(", UNKNOWN=").append(unknown);
        }
        sb.append(". Проверьте детали по отчету сканирования.");
        return sb.toString();
    }

    private DeveloperNotificationEntity buildNotification(
            Long developerUserId,
            Long scanId,
            String scanType,
            String severity,
            String title,
            String message,
            Instant createdAt) {
        DeveloperNotificationEntity entity = new DeveloperNotificationEntity();
        entity.setDeveloperUserId(developerUserId);
        entity.setScanId(scanId);
        entity.setScanType(scanType);
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

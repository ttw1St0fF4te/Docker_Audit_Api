package com.nn2.docker_audit_api.securityengineer.service;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.support.CronExpression;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.nn2.docker_audit_api.audit.context.AuditContextHolder;
import com.nn2.docker_audit_api.auth.repository.AppUserRepository;
import com.nn2.docker_audit_api.securityengineer.entity.CveScanScheduleEntity;
import com.nn2.docker_audit_api.securityengineer.repository.CveScanScheduleRepository;

@Component
public class CveScheduleExecutor {

    private static final Logger log = LoggerFactory.getLogger(CveScheduleExecutor.class);

    private final AppUserRepository appUserRepository;
    private final CveScannerService cveScannerService;
    private final CveScanScheduleRepository cveScanScheduleRepository;
    private final AuditContextHolder auditContextHolder;
    private final String schedulerUsername;

    public CveScheduleExecutor(
            AppUserRepository appUserRepository,
            CveScannerService cveScannerService,
            CveScanScheduleRepository cveScanScheduleRepository,
            AuditContextHolder auditContextHolder,
            @Value("${app.cve.scheduler.username:engineer}") String schedulerUsername) {
        this.appUserRepository = appUserRepository;
        this.cveScannerService = cveScannerService;
        this.cveScanScheduleRepository = cveScanScheduleRepository;
        this.auditContextHolder = auditContextHolder;
        this.schedulerUsername = schedulerUsername;
    }

    @Async
    public void runScheduledCveScan(Long scheduleId, Long hostId, String cronExpression, Runnable releaseLockAction) {
        String requestId = UUID.randomUUID().toString();
        auditContextHolder.runWith(requestId, schedulerUsername, () -> {
            try {
                Long startedBy = resolveSchedulerUserId();
                cveScannerService.runCveScan(hostId, startedBy);

                Instant completedAt = Instant.now();
                updateScheduleAfterAttempt(scheduleId, cronExpression, completedAt);
            } catch (Exception ex) {
                log.error("Ошибка автозапуска CVE-скана: scheduleId={}, hostId={}", scheduleId, hostId, ex);
                updateScheduleAfterAttempt(scheduleId, cronExpression, Instant.now());
            } finally {
                releaseLockAction.run();
            }
        });
    }

    private Long resolveSchedulerUserId() {
        return appUserRepository.findByUsername(schedulerUsername)
            .orElseThrow(() -> new IllegalStateException("Пользователь scheduler не найден: " + schedulerUsername))
            .getId();
    }

    @Transactional
    protected void updateScheduleAfterAttempt(Long scheduleId, String cronExpression, Instant attemptedAt) {
        CveScanScheduleEntity schedule = cveScanScheduleRepository.findById(scheduleId)
            .orElseThrow(() -> new IllegalStateException("CVE расписание не найдено: " + scheduleId));

        schedule.setLastRun(attemptedAt);
        schedule.setNextRun(calculateNextRun(cronExpression, attemptedAt));
        cveScanScheduleRepository.save(schedule);
    }

    private Instant calculateNextRun(String rawCronExpression, Instant referenceTime) {
        CronExpression cronExpression = parseCron(rawCronExpression);
        ZonedDateTime now = referenceTime.atZone(ZoneId.systemDefault());
        ZonedDateTime next = cronExpression.next(now);

        if (next == null) {
            throw new IllegalStateException("Не удалось вычислить next_run для cron: " + rawCronExpression);
        }
        return next.toInstant();
    }

    private CronExpression parseCron(String rawCronExpression) {
        if (rawCronExpression == null || rawCronExpression.isBlank()) {
            throw new IllegalStateException("cron_expression пустой");
        }

        String normalized = normalizeCronExpression(rawCronExpression);
        try {
            return CronExpression.parse(normalized);
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("Некорректный cron_expression: " + rawCronExpression, ex);
        }
    }

    private String normalizeCronExpression(String rawCronExpression) {
        String trimmed = rawCronExpression.trim().replaceAll("\\s+", " ");
        int parts = trimmed.split(" ").length;

        if (parts == 5) {
            return "0 " + trimmed;
        }
        return trimmed;
    }
}

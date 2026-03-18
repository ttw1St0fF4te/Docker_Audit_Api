package com.nn2.docker_audit_api.securityengineer.service;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.support.CronExpression;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.nn2.docker_audit_api.auth.repository.AppUserRepository;
import com.nn2.docker_audit_api.securityengineer.entity.AuditScheduleEntity;
import com.nn2.docker_audit_api.securityengineer.repository.AuditScheduleRepository;

@Component
public class AuditScheduleExecutor {

    private static final Logger log = LoggerFactory.getLogger(AuditScheduleExecutor.class);

    private final AppUserRepository appUserRepository;
    private final AuditService auditService;
    private final AuditScheduleRepository auditScheduleRepository;
    private final String schedulerUsername;

    public AuditScheduleExecutor(
            AppUserRepository appUserRepository,
            AuditService auditService,
            AuditScheduleRepository auditScheduleRepository,
            @Value("${app.audit.scheduler.username:engineer}") String schedulerUsername) {
        this.appUserRepository = appUserRepository;
        this.auditService = auditService;
        this.auditScheduleRepository = auditScheduleRepository;
        this.schedulerUsername = schedulerUsername;
    }

    @Async
    public void runScheduledAudit(Long scheduleId, Long hostId, String cronExpression, Runnable releaseLockAction) {
        try {
            Long startedBy = resolveSchedulerUserId();
            auditService.runAudit(hostId, startedBy);

            Instant completedAt = Instant.now();
            updateScheduleAfterAttempt(scheduleId, cronExpression, completedAt);
        } catch (Exception ex) {
            log.error("Ошибка автозапуска аудита: scheduleId={}, hostId={}", scheduleId, hostId, ex);
            updateScheduleAfterAttempt(scheduleId, cronExpression, Instant.now());
        } finally {
            releaseLockAction.run();
        }
    }

    private Long resolveSchedulerUserId() {
        return appUserRepository.findByUsername(schedulerUsername)
            .orElseThrow(() -> new IllegalStateException("Пользователь scheduler не найден: " + schedulerUsername))
            .getId();
    }

    @Transactional
    protected void updateScheduleAfterAttempt(Long scheduleId, String cronExpression, Instant attemptedAt) {
        AuditScheduleEntity schedule = auditScheduleRepository.findById(scheduleId)
            .orElseThrow(() -> new IllegalStateException("Расписание не найдено: " + scheduleId));

        schedule.setLastRun(attemptedAt);
        schedule.setNextRun(calculateNextRun(cronExpression, attemptedAt));
        auditScheduleRepository.save(schedule);
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
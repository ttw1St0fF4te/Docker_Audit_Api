package com.nn2.docker_audit_api.securityengineer.service;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.nn2.docker_audit_api.securityengineer.entity.AuditScheduleEntity;
import com.nn2.docker_audit_api.securityengineer.repository.AuditScheduleRepository;
import com.nn2.docker_audit_api.securityengineer.repository.ScanRepository;

@Component
public class AuditScheduleJob {

    private static final Logger log = LoggerFactory.getLogger(AuditScheduleJob.class);

    private final AuditScheduleRepository auditScheduleRepository;
    private final ScanRepository scanRepository;
    private final AuditScheduleExecutor auditScheduleExecutor;
    private final Set<Long> runningHosts = ConcurrentHashMap.newKeySet();

    public AuditScheduleJob(
            AuditScheduleRepository auditScheduleRepository,
            ScanRepository scanRepository,
            AuditScheduleExecutor auditScheduleExecutor) {
        this.auditScheduleRepository = auditScheduleRepository;
        this.scanRepository = scanRepository;
        this.auditScheduleExecutor = auditScheduleExecutor;
    }

    @Scheduled(fixedDelayString = "${app.audit.scheduler.poll-delay-ms:60000}")
    public void pollDueSchedules() {
        Instant now = Instant.now();
        List<AuditScheduleEntity> schedules = auditScheduleRepository.findByActiveTrueOrderByIdAsc();

        for (AuditScheduleEntity schedule : schedules) {
            if (!isDue(schedule, now)) {
                continue;
            }
            dispatch(schedule);
        }
    }

    private boolean isDue(AuditScheduleEntity schedule, Instant now) {
        Instant nextRun = schedule.getNextRun();
        return nextRun == null || !nextRun.isAfter(now);
    }

    private void dispatch(AuditScheduleEntity schedule) {
        Long hostId = schedule.getHostId();
        if (hostId == null) {
            log.warn("Пропущено расписание {}: host_id не задан", schedule.getId());
            return;
        }

        if (!runningHosts.add(hostId)) {
            log.debug("Пропуск scheduleId={} для hostId={}: уже выполняется в scheduler", schedule.getId(), hostId);
            return;
        }

        if (scanRepository.existsByHostIdAndStatus(hostId, "RUNNING")) {
            log.info("Пропуск scheduleId={} для hostId={}: найден RUNNING scan", schedule.getId(), hostId);
            runningHosts.remove(hostId);
            return;
        }

        auditScheduleExecutor.runScheduledAudit(
            schedule.getId(),
            hostId,
            schedule.getCronExpression(),
            () -> runningHosts.remove(hostId));
    }
}

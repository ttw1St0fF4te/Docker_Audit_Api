package com.nn2.docker_audit_api.securityengineer.service;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.nn2.docker_audit_api.securityengineer.entity.CveScanScheduleEntity;
import com.nn2.docker_audit_api.securityengineer.repository.CveScanRepository;
import com.nn2.docker_audit_api.securityengineer.repository.CveScanScheduleRepository;

@Component
public class CveScheduleJob {

    private static final Logger log = LoggerFactory.getLogger(CveScheduleJob.class);

    private final CveScanScheduleRepository cveScanScheduleRepository;
    private final CveScanRepository cveScanRepository;
    private final CveScheduleExecutor cveScheduleExecutor;
    private final Set<Long> runningHosts = ConcurrentHashMap.newKeySet();

    public CveScheduleJob(
            CveScanScheduleRepository cveScanScheduleRepository,
            CveScanRepository cveScanRepository,
            CveScheduleExecutor cveScheduleExecutor) {
        this.cveScanScheduleRepository = cveScanScheduleRepository;
        this.cveScanRepository = cveScanRepository;
        this.cveScheduleExecutor = cveScheduleExecutor;
    }

    @Scheduled(fixedDelayString = "${app.cve.scheduler.poll-delay-ms:60000}")
    public void pollDueCveSchedules() {
        Instant now = Instant.now();
        List<CveScanScheduleEntity> schedules = cveScanScheduleRepository.findByActiveTrueOrderByIdAsc();

        for (CveScanScheduleEntity schedule : schedules) {
            if (!isDue(schedule, now)) {
                continue;
            }
            dispatch(schedule);
        }
    }

    private boolean isDue(CveScanScheduleEntity schedule, Instant now) {
        Instant nextRun = schedule.getNextRun();
        return nextRun == null || !nextRun.isAfter(now);
    }

    private void dispatch(CveScanScheduleEntity schedule) {
        Long hostId = schedule.getHostId();
        if (hostId == null) {
            log.warn("Пропущено CVE-расписание {}: host_id не задан", schedule.getId());
            return;
        }

        if (!runningHosts.add(hostId)) {
            log.debug("Пропуск CVE scheduleId={} для hostId={}: уже выполняется в scheduler", schedule.getId(), hostId);
            return;
        }

        if (cveScanRepository.existsByHostIdAndStatus(hostId, "RUNNING")) {
            log.info("Пропуск CVE scheduleId={} для hostId={}: найден RUNNING CVE scan", schedule.getId(), hostId);
            runningHosts.remove(hostId);
            return;
        }

        cveScheduleExecutor.runScheduledCveScan(
            schedule.getId(),
            hostId,
            schedule.getCronExpression(),
            () -> runningHosts.remove(hostId));
    }
}

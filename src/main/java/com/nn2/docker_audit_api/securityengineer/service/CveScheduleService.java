package com.nn2.docker_audit_api.securityengineer.service;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.stream.Stream;

import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.support.CronExpression;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import com.nn2.docker_audit_api.securityengineer.dto.CveScheduleResponse;
import com.nn2.docker_audit_api.securityengineer.dto.CveSchedulesPageResponse;
import com.nn2.docker_audit_api.securityengineer.dto.CveScheduleUpsertRequest;
import com.nn2.docker_audit_api.securityengineer.entity.CveScanScheduleEntity;
import com.nn2.docker_audit_api.securityengineer.entity.DockerHostEntity;
import com.nn2.docker_audit_api.securityengineer.repository.CveScanScheduleRepository;
import com.nn2.docker_audit_api.securityengineer.repository.DockerHostRepository;

@Service
public class CveScheduleService {

    private static final int DEFAULT_PAGE = 0;
    private static final int DEFAULT_SIZE = 50;
    private static final int MAX_SIZE = 200;

    private final DockerHostRepository dockerHostRepository;
    private final CveScanScheduleRepository cveScanScheduleRepository;

    public CveScheduleService(
            DockerHostRepository dockerHostRepository,
            CveScanScheduleRepository cveScanScheduleRepository) {
        this.dockerHostRepository = dockerHostRepository;
        this.cveScanScheduleRepository = cveScanScheduleRepository;
    }

    @Transactional
    public CveScheduleResponse upsertSchedule(CveScheduleUpsertRequest request) {
        DockerHostEntity host = dockerHostRepository.findById(request.hostId())
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Docker-хост не найден"));

        if (host.isDeleted()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Нельзя настраивать расписание для удаленного Docker-хоста");
        }

        String normalizedCron = normalizeCronExpression(request.cronExpression());
        validateCron(normalizedCron, request.cronExpression());
        boolean active = request.active() == null || request.active();

        if (active && !host.isActive()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Нельзя активировать расписание для неактивного Docker-хоста");
        }

        CveScanScheduleEntity schedule = cveScanScheduleRepository.findFirstByHostIdOrderByIdDesc(host.getId())
            .orElseGet(CveScanScheduleEntity::new);

        schedule.setHostId(host.getId());
        schedule.setCronExpression(request.cronExpression().trim().replaceAll("\\s+", " "));
        schedule.setActive(active);

        if (active) {
            Instant now = Instant.now();
            schedule.setNextRun(calculateNextRun(normalizedCron, now));
        } else {
            schedule.setNextRun(null);
        }

        CveScanScheduleEntity saved = cveScanScheduleRepository.save(schedule);
        return toScheduleResponse(saved);
    }

    public CveSchedulesPageResponse listSchedules(Integer page, Integer size, Long hostId, Boolean active) {
        int safePage = normalizePage(page);
        int safeSize = normalizeSize(size);

        List<CveScanScheduleEntity> all = cveScanScheduleRepository.findAll(
            Sort.by(Sort.Direction.ASC, "hostId").and(Sort.by(Sort.Direction.ASC, "id")));
        Stream<CveScanScheduleEntity> stream = all.stream();

        if (hostId != null) {
            stream = stream.filter(schedule -> hostId.equals(schedule.getHostId()));
        }

        if (active != null) {
            stream = stream.filter(schedule -> schedule.isActive() == active);
        }

        List<CveScanScheduleEntity> filtered = stream.toList();
        List<CveScheduleResponse> pagedItems = paginate(filtered, safePage, safeSize).stream()
            .map(this::toScheduleResponse)
            .toList();

        return new CveSchedulesPageResponse(pagedItems, filtered.size(), safePage, safeSize);
    }

    private CveScheduleResponse toScheduleResponse(CveScanScheduleEntity schedule) {
        return new CveScheduleResponse(
            schedule.getId(),
            schedule.getHostId(),
            schedule.getCronExpression(),
            schedule.isActive(),
            toIso(schedule.getLastRun()),
            toIso(schedule.getNextRun()));
    }

    private <T> List<T> paginate(List<T> items, int page, int size) {
        int from = page * size;
        if (from >= items.size()) {
            return List.of();
        }
        int to = Math.min(from + size, items.size());
        return items.subList(from, to);
    }

    private int normalizePage(Integer page) {
        if (page == null || page < 0) {
            return DEFAULT_PAGE;
        }
        return page;
    }

    private int normalizeSize(Integer size) {
        if (size == null) {
            return DEFAULT_SIZE;
        }
        if (size < 1) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "size должен быть >= 1");
        }
        if (size > MAX_SIZE) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "size не должен быть больше " + MAX_SIZE);
        }
        return size;
    }

    private void validateCron(String normalizedCron, String originalCron) {
        try {
            CronExpression.parse(normalizedCron);
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Некорректный cron_expression: " + originalCron);
        }
    }

    private Instant calculateNextRun(String normalizedCronExpression, Instant referenceTime) {
        CronExpression cronExpression = CronExpression.parse(normalizedCronExpression);
        ZonedDateTime now = referenceTime.atZone(ZoneId.systemDefault());
        ZonedDateTime next = cronExpression.next(now);
        if (next == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Не удалось вычислить next_run для cron_expression");
        }
        return next.toInstant();
    }

    private String normalizeCronExpression(String rawCronExpression) {
        String trimmed = rawCronExpression.trim().replaceAll("\\s+", " ");
        int parts = trimmed.split(" ").length;
        if (parts == 5) {
            return "0 " + trimmed;
        }
        return trimmed;
    }

    private String toIso(Instant instant) {
        return instant == null ? null : instant.toString();
    }
}

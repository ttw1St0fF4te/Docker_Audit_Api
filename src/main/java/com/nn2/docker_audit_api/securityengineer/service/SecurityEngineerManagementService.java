package com.nn2.docker_audit_api.securityengineer.service;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.support.CronExpression;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import com.nn2.docker_audit_api.securityengineer.dto.AuditScheduleResponse;
import com.nn2.docker_audit_api.securityengineer.dto.AuditSchedulesPageResponse;
import com.nn2.docker_audit_api.securityengineer.dto.AuditScheduleUpsertRequest;
import com.nn2.docker_audit_api.securityengineer.dto.CisRuleItemResponse;
import com.nn2.docker_audit_api.securityengineer.dto.CisRulesPageResponse;
import com.nn2.docker_audit_api.securityengineer.dto.DockerHostItemResponse;
import com.nn2.docker_audit_api.securityengineer.dto.DockerHostsPageResponse;
import com.nn2.docker_audit_api.securityengineer.dto.NotificationSettingsResponse;
import com.nn2.docker_audit_api.securityengineer.entity.AuditScheduleEntity;
import com.nn2.docker_audit_api.securityengineer.entity.CisRuleEntity;
import com.nn2.docker_audit_api.securityengineer.entity.DockerHostEntity;
import com.nn2.docker_audit_api.securityengineer.repository.AuditScheduleRepository;
import com.nn2.docker_audit_api.securityengineer.repository.CisRuleRepository;
import com.nn2.docker_audit_api.securityengineer.repository.DockerHostRepository;

@Service
public class SecurityEngineerManagementService {

    private static final int DEFAULT_PAGE = 0;
    private static final int DEFAULT_SIZE = 50;
    private static final int MAX_SIZE = 200;

    private final CisRuleRepository cisRuleRepository;
    private final DockerHostRepository dockerHostRepository;
    private final AuditScheduleRepository auditScheduleRepository;
    private final NotificationSettingsService notificationSettingsService;

    public SecurityEngineerManagementService(
            CisRuleRepository cisRuleRepository,
            DockerHostRepository dockerHostRepository,
            AuditScheduleRepository auditScheduleRepository,
            NotificationSettingsService notificationSettingsService) {
        this.cisRuleRepository = cisRuleRepository;
        this.dockerHostRepository = dockerHostRepository;
        this.auditScheduleRepository = auditScheduleRepository;
        this.notificationSettingsService = notificationSettingsService;
    }

    public NotificationSettingsResponse getNotificationSettings() {
        return notificationSettingsService.getSettings();
    }

    public NotificationSettingsResponse updateNotificationSettings(String minSeverity) {
        return notificationSettingsService.updateSettings(minSeverity);
    }

    public CisRulesPageResponse listRules(Integer page, Integer size, String severity, Boolean enabled) {
        int safePage = normalizePage(page);
        int safeSize = normalizeSize(size);

        List<CisRuleEntity> all = cisRuleRepository.findAll(Sort.by(Sort.Direction.ASC, "cisCode"));
        Stream<CisRuleEntity> stream = all.stream();

        if (severity != null && !severity.isBlank()) {
            String normalizedSeverity = severity.trim().toUpperCase(Locale.ROOT);
            stream = stream.filter(rule -> normalizedSeverity.equalsIgnoreCase(rule.getSeverity()));
        }

        if (enabled != null) {
            stream = stream.filter(rule -> rule.isEnabled() == enabled);
        }

        List<CisRuleEntity> filtered = stream.toList();
        List<CisRuleItemResponse> pagedItems = paginate(filtered, safePage, safeSize).stream()
            .map(this::toRuleItem)
            .toList();

        return new CisRulesPageResponse(pagedItems, filtered.size(), safePage, safeSize);
    }

    @Transactional
    public CisRuleItemResponse updateRuleEnabled(Long ruleId, boolean enabled) {
        CisRuleEntity rule = cisRuleRepository.findById(ruleId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "CIS-правило не найдено"));

        rule.setEnabled(enabled);
        return toRuleItem(cisRuleRepository.save(rule));
    }

    public DockerHostsPageResponse listHosts(Integer page, Integer size, Boolean active) {
        int safePage = normalizePage(page);
        int safeSize = normalizeSize(size);

        List<DockerHostEntity> all = dockerHostRepository.findAll(Sort.by(Sort.Direction.ASC, "id"));
        Stream<DockerHostEntity> stream = all.stream().filter(host -> !host.isDeleted());

        if (active != null) {
            stream = stream.filter(host -> host.isActive() == active);
        }

        List<DockerHostEntity> filtered = stream.toList();
        List<DockerHostItemResponse> pagedItems = paginate(filtered, safePage, safeSize).stream()
            .map(this::toHostItem)
            .toList();

        return new DockerHostsPageResponse(pagedItems, filtered.size(), safePage, safeSize);
    }

    @Transactional
    public AuditScheduleResponse upsertSchedule(AuditScheduleUpsertRequest request) {
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

        AuditScheduleEntity schedule = auditScheduleRepository.findFirstByHostIdOrderByIdDesc(host.getId())
            .orElseGet(AuditScheduleEntity::new);

        schedule.setHostId(host.getId());
        schedule.setCronExpression(request.cronExpression().trim().replaceAll("\\s+", " "));
        schedule.setActive(active);

        if (active) {
            Instant now = Instant.now();
            schedule.setNextRun(calculateNextRun(normalizedCron, now));
        } else {
            schedule.setNextRun(null);
        }
        AuditScheduleEntity saved = auditScheduleRepository.save(schedule);
        return toScheduleResponse(saved);
    }

    public AuditSchedulesPageResponse listSchedules(Integer page, Integer size, Long hostId, Boolean active) {
        int safePage = normalizePage(page);
        int safeSize = normalizeSize(size);

        List<AuditScheduleEntity> all = auditScheduleRepository.findAll(
            Sort.by(Sort.Direction.ASC, "hostId").and(Sort.by(Sort.Direction.ASC, "id")));
        Stream<AuditScheduleEntity> stream = all.stream();

        if (hostId != null) {
            stream = stream.filter(schedule -> hostId.equals(schedule.getHostId()));
        }

        if (active != null) {
            stream = stream.filter(schedule -> schedule.isActive() == active);
        }

        List<AuditScheduleEntity> filtered = stream.toList();
        List<AuditScheduleResponse> pagedItems = paginate(filtered, safePage, safeSize).stream()
            .map(this::toScheduleResponse)
            .toList();

        return new AuditSchedulesPageResponse(pagedItems, filtered.size(), safePage, safeSize);
    }

    private CisRuleItemResponse toRuleItem(CisRuleEntity rule) {
        return new CisRuleItemResponse(
            rule.getId(),
            rule.getCisCode(),
            rule.getName(),
            rule.getDescription(),
            rule.getSeverity(),
            rule.getRecommendation(),
            rule.isEnabled());
    }

    private DockerHostItemResponse toHostItem(DockerHostEntity host) {
        return new DockerHostItemResponse(
            host.getId(),
            host.getName(),
            host.getBaseUrl(),
            host.getHostType(),
            host.isTlsEnabled(),
            host.getAuthType(),
            host.getCertPath(),
            host.isActive(),
            host.isDeleted(),
            toIso(host.getCreatedAt()));
    }

    private AuditScheduleResponse toScheduleResponse(AuditScheduleEntity schedule) {
        return new AuditScheduleResponse(
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

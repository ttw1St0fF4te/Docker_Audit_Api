package com.nn2.docker_audit_api.admin.service;

import java.time.Instant;
import java.util.List;
import java.util.Locale;

import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import com.nn2.docker_audit_api.admin.dto.AdminDockerHostConnectionTestRequest;
import com.nn2.docker_audit_api.admin.dto.AdminDockerHostConnectionTestResponse;
import com.nn2.docker_audit_api.admin.dto.AdminDockerHostDeleteResponse;
import com.nn2.docker_audit_api.admin.dto.AdminDockerHostUpsertRequest;
import com.nn2.docker_audit_api.securityengineer.docker.DockerClientService;
import com.nn2.docker_audit_api.securityengineer.docker.DockerConnectionException;
import com.nn2.docker_audit_api.securityengineer.dto.DockerHostItemResponse;
import com.nn2.docker_audit_api.securityengineer.dto.DockerHostsPageResponse;
import com.nn2.docker_audit_api.securityengineer.entity.AuditScheduleEntity;
import com.nn2.docker_audit_api.securityengineer.entity.DockerHostEntity;
import com.nn2.docker_audit_api.securityengineer.model.DockerHostType;
import com.nn2.docker_audit_api.securityengineer.repository.AuditScheduleRepository;
import com.nn2.docker_audit_api.securityengineer.repository.DockerHostRepository;
import com.nn2.docker_audit_api.securityengineer.repository.ScanRepository;

@Service
public class AdminDockerHostService {

    private static final int DEFAULT_PAGE = 0;
    private static final int DEFAULT_SIZE = 20;
    private static final int MAX_SIZE = 200;

    private final DockerHostRepository dockerHostRepository;
    private final AuditScheduleRepository auditScheduleRepository;
    private final ScanRepository scanRepository;
    private final DockerClientService dockerClientService;

    public AdminDockerHostService(
            DockerHostRepository dockerHostRepository,
            AuditScheduleRepository auditScheduleRepository,
            ScanRepository scanRepository,
            DockerClientService dockerClientService) {
        this.dockerHostRepository = dockerHostRepository;
        this.auditScheduleRepository = auditScheduleRepository;
        this.scanRepository = scanRepository;
        this.dockerClientService = dockerClientService;
    }

    public DockerHostsPageResponse listHosts(Integer page, Integer size, Boolean active, Boolean deleted) {
        int safePage = normalizePage(page);
        int safeSize = normalizeSize(size);

        List<DockerHostEntity> all = dockerHostRepository.findAll(Sort.by(Sort.Direction.ASC, "id"));

        List<DockerHostEntity> filtered = all.stream()
            .filter(host -> active == null || host.isActive() == active)
            .filter(host -> deleted == null || host.isDeleted() == deleted)
            .toList();

        int from = safePage * safeSize;
        if (from >= filtered.size()) {
            return new DockerHostsPageResponse(List.of(), filtered.size(), safePage, safeSize);
        }
        int to = Math.min(from + safeSize, filtered.size());

        List<DockerHostItemResponse> items = filtered.subList(from, to).stream()
            .map(this::toItem)
            .toList();

        return new DockerHostsPageResponse(items, filtered.size(), safePage, safeSize);
    }

    public AdminDockerHostConnectionTestResponse testConnection(AdminDockerHostConnectionTestRequest request) {
        String baseUrl = normalizeBaseUrl(request.baseUrl(), request.hostType());
        try {
            int containers = dockerClientService.listContainerSnapshots(baseUrl).size();
            return new AdminDockerHostConnectionTestResponse(
                true,
                "Подключение успешно. Контейнеров найдено: " + containers,
                containers);
        } catch (DockerConnectionException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Подключение к Docker-хосту не удалось: " + ex.getMessage());
        }
    }

    @Transactional
    public DockerHostItemResponse createHost(AdminDockerHostUpsertRequest request) {
        String baseUrl = normalizeBaseUrl(request.baseUrl(), request.hostType());

        if (dockerHostRepository.existsByBaseUrlIgnoreCase(baseUrl)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Хост с таким endpoint уже существует");
        }

        // По требованию этапа хост сохраняем только после успешного теста подключения.
        testConnection(new AdminDockerHostConnectionTestRequest(baseUrl, request.hostType()));

        DockerHostEntity host = new DockerHostEntity();
        host.setName(request.name().trim());
        host.setBaseUrl(baseUrl);
        host.setHostType(request.hostType().name());
        host.setTlsEnabled(Boolean.TRUE.equals(request.tlsEnabled()));
        host.setAuthType(normalizeNullable(request.authType()));
        host.setCertPath(normalizeNullable(request.certPath()));
        host.setActive(request.active() == null || request.active());
        host.setDeleted(false);
        host.setCreatedAt(Instant.now());

        return toItem(dockerHostRepository.save(host));
    }

    @Transactional
    public DockerHostItemResponse updateHost(Long hostId, AdminDockerHostUpsertRequest request) {
        DockerHostEntity host = requireHost(hostId);

        String baseUrl = normalizeBaseUrl(request.baseUrl(), request.hostType());
        dockerHostRepository.findByBaseUrlIgnoreCase(baseUrl)
            .filter(existing -> !existing.getId().equals(hostId))
            .ifPresent(existing -> {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Хост с таким endpoint уже существует");
            });

        testConnection(new AdminDockerHostConnectionTestRequest(baseUrl, request.hostType()));

        host.setName(request.name().trim());
        host.setBaseUrl(baseUrl);
        host.setHostType(request.hostType().name());
        host.setTlsEnabled(Boolean.TRUE.equals(request.tlsEnabled()));
        host.setAuthType(normalizeNullable(request.authType()));
        host.setCertPath(normalizeNullable(request.certPath()));

        if (request.active() != null) {
            setHostActiveInternal(host, request.active());
        }

        return toItem(dockerHostRepository.save(host));
    }

    @Transactional
    public DockerHostItemResponse setHostActive(Long hostId, boolean active) {
        DockerHostEntity host = requireHost(hostId);
        setHostActiveInternal(host, active);
        return toItem(dockerHostRepository.save(host));
    }

    @Transactional
    public AdminDockerHostDeleteResponse softDelete(Long hostId) {
        DockerHostEntity host = requireHost(hostId);

        if (host.isDeleted()) {
            return new AdminDockerHostDeleteResponse(host.getId(), host.getName(), false, "Хост уже помечен как удаленный");
        }

        if (auditScheduleRepository.existsByHostIdAndActiveTrue(hostId)) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Нельзя мягко удалить хост, пока для него есть активное расписание");
        }

        host.setDeleted(true);
        host.setActive(false);
        dockerHostRepository.save(host);

        return new AdminDockerHostDeleteResponse(host.getId(), host.getName(), false, "Хост мягко удален");
    }

    @Transactional
    public DockerHostItemResponse restore(Long hostId) {
        DockerHostEntity host = requireHost(hostId);

        if (!host.isDeleted()) {
            return toItem(host);
        }

        host.setDeleted(false);
        return toItem(dockerHostRepository.save(host));
    }

    @Transactional
    public AdminDockerHostDeleteResponse hardDelete(Long hostId) {
        DockerHostEntity host = requireHost(hostId);

        if (scanRepository.existsByHostId(hostId)) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Нельзя удалить хост физически: для него уже есть сканирования");
        }

        // По бизнес-правилу физическое удаление разрешено при отсутствии сканов,
        // даже если расписания были созданы.
        auditScheduleRepository.deleteByHostId(hostId);
        dockerHostRepository.delete(host);

        return new AdminDockerHostDeleteResponse(host.getId(), host.getName(), true, "Хост удален физически");
    }

    private DockerHostEntity requireHost(Long hostId) {
        return dockerHostRepository.findById(hostId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Docker-хост не найден"));
    }

    private void setHostActiveInternal(DockerHostEntity host, boolean active) {
        if (active && host.isDeleted()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Нельзя активировать мягко удаленный хост");
        }

        host.setActive(active);

        if (!active) {
            // При отключении хоста деактивируем его расписания, чтобы scheduler не пытался запускать сканы.
            List<AuditScheduleEntity> schedules = auditScheduleRepository.findByHostIdOrderByIdAsc(host.getId());
            for (AuditScheduleEntity schedule : schedules) {
                if (schedule.isActive()) {
                    schedule.setActive(false);
                    schedule.setNextRun(null);
                }
            }
            if (!schedules.isEmpty()) {
                auditScheduleRepository.saveAll(schedules);
            }
        }
    }

    private DockerHostItemResponse toItem(DockerHostEntity host) {
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
            host.getCreatedAt() == null ? null : host.getCreatedAt().toString());
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
        if (size < 1 || size > MAX_SIZE) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "size должен быть в диапазоне 1.." + MAX_SIZE);
        }
        return size;
    }

    private String normalizeBaseUrl(String rawBaseUrl, DockerHostType hostType) {
        String baseUrl = rawBaseUrl.trim();
        String lower = baseUrl.toLowerCase(Locale.ROOT);

        if (hostType == DockerHostType.LOCAL_SOCKET && !lower.startsWith("unix://")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Для LOCAL_SOCKET endpoint должен начинаться с unix://");
        }

        if (hostType == DockerHostType.REMOTE_TCP && !lower.startsWith("tcp://")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Для REMOTE_TCP endpoint должен начинаться с tcp://");
        }

        return baseUrl;
    }

    private String normalizeNullable(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }
}

package com.nn2.docker_audit_api.developer.service;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.github.dockerjava.api.async.ResultCallbackTemplate;
import com.github.dockerjava.api.model.Container;
import com.github.dockerjava.api.model.Statistics;
import com.nn2.docker_audit_api.developer.dto.dashboard.DeveloperDashboardContainerLoadItemResponse;
import com.nn2.docker_audit_api.developer.dto.dashboard.DeveloperDashboardContainerLoadResponse;
import com.nn2.docker_audit_api.developer.dto.dashboard.DeveloperDashboardHostContainerStateItemResponse;
import com.nn2.docker_audit_api.developer.dto.dashboard.DeveloperDashboardHostContainerStateResponse;
import com.nn2.docker_audit_api.developer.dto.dashboard.DeveloperDashboardSeverityBreakdownResponse;
import com.nn2.docker_audit_api.developer.dto.dashboard.DeveloperDashboardTopRiskContainerItemResponse;
import com.nn2.docker_audit_api.developer.dto.dashboard.DeveloperDashboardTopRiskContainersResponse;
import com.nn2.docker_audit_api.securityengineer.config.DockerAuditProperties;
import com.nn2.docker_audit_api.securityengineer.docker.DockerClientFactory;
import com.nn2.docker_audit_api.securityengineer.docker.DockerClientService;
import com.nn2.docker_audit_api.securityengineer.docker.model.ContainerSnapshot;
import com.nn2.docker_audit_api.securityengineer.entity.DockerHostEntity;
import com.nn2.docker_audit_api.securityengineer.entity.ScanEntity;
import com.nn2.docker_audit_api.securityengineer.repository.DockerHostRepository;
import com.nn2.docker_audit_api.securityengineer.repository.ScanRepository;

@Service
public class DeveloperDashboardService {

    private static final DateTimeFormatter CH_DATE_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
        .withZone(ZoneOffset.UTC);

    private final DockerHostRepository dockerHostRepository;
    private final DockerClientService dockerClientService;
    private final DockerClientFactory dockerClientFactory;
    private final DockerAuditProperties dockerAuditProperties;
    private final ScanRepository scanRepository;
    private final JdbcTemplate clickHouseJdbcTemplate;

    public DeveloperDashboardService(
            DockerHostRepository dockerHostRepository,
            DockerClientService dockerClientService,
            DockerClientFactory dockerClientFactory,
            DockerAuditProperties dockerAuditProperties,
            ScanRepository scanRepository,
            @Qualifier("clickHouseJdbcTemplate") JdbcTemplate clickHouseJdbcTemplate) {
        this.dockerHostRepository = dockerHostRepository;
        this.dockerClientService = dockerClientService;
        this.dockerClientFactory = dockerClientFactory;
        this.dockerAuditProperties = dockerAuditProperties;
        this.scanRepository = scanRepository;
        this.clickHouseJdbcTemplate = clickHouseJdbcTemplate;
    }

    public DeveloperDashboardHostContainerStateResponse getContainerStateByHosts(Long hostId) {
        List<DockerHostEntity> hosts = resolveHosts(hostId);
        List<DeveloperDashboardHostContainerStateItemResponse> items = new ArrayList<>();

        for (DockerHostEntity host : hosts) {
            try {
                List<ContainerSnapshot> snapshots = dockerClientService.listContainerSnapshots(host.getBaseUrl());
                int running = 0;
                int exited = 0;
                int restarting = 0;
                int unhealthy = 0;

                for (ContainerSnapshot snapshot : snapshots) {
                    String state = normalize(snapshot.state());
                    String health = normalize(snapshot.healthStatus());

                    if ("running".equals(state)) {
                        running++;
                    } else if ("exited".equals(state)) {
                        exited++;
                    } else if ("restarting".equals(state)) {
                        restarting++;
                    }

                    if ("unhealthy".equals(health)) {
                        unhealthy++;
                    }
                }

                items.add(new DeveloperDashboardHostContainerStateItemResponse(
                    host.getId(),
                    host.getName(),
                    snapshots.size(),
                    running,
                    exited,
                    restarting,
                    unhealthy,
                    null));
            } catch (Exception ex) {
                items.add(new DeveloperDashboardHostContainerStateItemResponse(
                    host.getId(),
                    host.getName(),
                    0,
                    0,
                    0,
                    0,
                    0,
                    summarizeException(ex)));
            }
        }

        return new DeveloperDashboardHostContainerStateResponse(Instant.now().toString(), items);
    }

    public DeveloperDashboardContainerLoadResponse getContainerLoad(Long hostId, Integer limitRaw) {
        int limit = normalizeLimit(limitRaw, 10, 100);
        List<DockerHostEntity> hosts = resolveHosts(hostId);
        List<DeveloperDashboardContainerLoadItemResponse> items = new ArrayList<>();

        for (DockerHostEntity host : hosts) {
            try {
                String reachableHostUrl = dockerClientService.resolveReachableHostUrl(host.getBaseUrl());
                try (var client = dockerClientFactory.createClient(
                    reachableHostUrl,
                    dockerAuditProperties.getConnectTimeout(),
                    dockerAuditProperties.getReadTimeout())) {
                    List<Container> containers = client.listContainersCmd().withShowAll(true).exec();
                    for (Container container : containers) {
                        try {
                            String containerState = normalize(container.getState());
                            if (!"running".equals(containerState)) {
                                items.add(new DeveloperDashboardContainerLoadItemResponse(
                                    host.getId(),
                                    host.getName(),
                                    container.getId(),
                                    extractContainerName(container),
                                    container.getState(),
                                    0.0d,
                                    0L,
                                    0L,
                                    0.0d));
                                continue;
                            }

                            Statistics stats = fetchStatsSnapshot(client, container.getId());
                            double cpuPercent = calculateCpuPercent(stats);
                            long memoryUsage = readMemoryUsage(stats);
                            long memoryLimit = readMemoryLimit(stats);
                            double memoryPercent = memoryLimit > 0 ? (memoryUsage * 100.0d / memoryLimit) : 0.0d;

                            items.add(new DeveloperDashboardContainerLoadItemResponse(
                                host.getId(),
                                host.getName(),
                                container.getId(),
                                extractContainerName(container),
                                container.getState(),
                                round2(cpuPercent),
                                memoryUsage,
                                memoryLimit,
                                round2(memoryPercent)));
                        } catch (Exception ignored) {
                            items.add(new DeveloperDashboardContainerLoadItemResponse(
                                host.getId(),
                                host.getName(),
                                container.getId(),
                                extractContainerName(container),
                                container.getState(),
                                0.0d,
                                0L,
                                0L,
                                0.0d));
                        }
                    }
                }
            } catch (Exception ignored) {
                // Ignored intentionally: one broken host should not block dashboard data for other hosts.
            }
        }

        items.sort(Comparator
            .comparingDouble(DeveloperDashboardContainerLoadItemResponse::cpuPercent).reversed()
            .thenComparingLong(DeveloperDashboardContainerLoadItemResponse::memoryUsageBytes).reversed());

        items = items.stream()
            .filter(item -> item.cpuPercent() > 0.0d || item.memoryUsageBytes() > 0L || item.memoryPercent() > 0.0d)
            .toList();

        if (items.size() > limit) {
            items = new ArrayList<>(items.subList(0, limit));
        }

        return new DeveloperDashboardContainerLoadResponse(Instant.now().toString(), limit, items);
    }

    public DeveloperDashboardTopRiskContainersResponse getTopRiskContainers(Long hostId, Integer limitRaw) {
        int limit = normalizeLimit(limitRaw, 10, 100);
        if (hostId != null) {
            resolveHost(hostId);
        }

        Optional<ScanEntity> maybeScan = hostId == null
            ? scanRepository.findTopByStatusOrderByStartedAtDesc("COMPLETED")
            : scanRepository.findTopByHostIdAndStatusOrderByStartedAtDesc(hostId, "COMPLETED");

        if (maybeScan.isEmpty()) {
            return new DeveloperDashboardTopRiskContainersResponse(Instant.now().toString(), null, limit, List.of());
        }

        ScanEntity scan = maybeScan.get();
        String sql = """
            SELECT
                toInt64(host_id) AS host_id,
                container_name,
                toInt64(sumIf(1, passed = 0)) AS failed_checks,
                max(multiIf(severity = 'CRITICAL', 4, severity = 'HIGH', 3, severity = 'MEDIUM', 2, 1)) AS severity_rank
            FROM audit_analytics.violations_log
            WHERE scan_id = ?
              AND passed = 0
            GROUP BY host_id, container_name
            ORDER BY failed_checks DESC, severity_rank DESC
            LIMIT ?
            """;

        Map<Long, String> hostNames = loadHostNames();
        List<DeveloperDashboardTopRiskContainerItemResponse> items = clickHouseJdbcTemplate.query(
            sql,
            (rs, rowNum) -> {
                Long hId = rs.getLong("host_id");
                return new DeveloperDashboardTopRiskContainerItemResponse(
                    scan.getId(),
                    hId,
                    hostNames.getOrDefault(hId, "host-" + hId),
                    rs.getString("container_name"),
                    rs.getLong("failed_checks"),
                    severityFromRank(rs.getInt("severity_rank")));
            },
            scan.getId(),
            limit);

        return new DeveloperDashboardTopRiskContainersResponse(Instant.now().toString(), scan.getId(), limit, items);
    }

    public DeveloperDashboardSeverityBreakdownResponse getSeverityBreakdown(Long hostId, String periodRaw) {
        if (hostId != null) {
            resolveHost(hostId);
        }

        String period = periodRaw == null || periodRaw.isBlank()
            ? "24H"
            : periodRaw.trim().toUpperCase(Locale.ROOT);

        Instant to = Instant.now();
        Instant from = switch (period) {
            case "24H" -> to.minusSeconds(24 * 60 * 60);
            case "7D" -> to.minusSeconds(7L * 24 * 60 * 60);
            default -> throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "period должен быть 24H или 7D");
        };

        String sql = """
            SELECT
                toInt64(sumIf(1, passed = 0 AND severity = 'CRITICAL')) AS critical_count,
                toInt64(sumIf(1, passed = 0 AND severity = 'HIGH')) AS high_count,
                toInt64(sumIf(1, passed = 0 AND severity = 'MEDIUM')) AS medium_count,
                toInt64(sumIf(1, passed = 0 AND severity = 'LOW')) AS low_count,
                toInt64(sumIf(1, passed = 0)) AS total_failed
            FROM audit_analytics.violations_log
            WHERE timestamp >= toDateTime(?)
              AND timestamp < toDateTime(?)
              %s
            """.formatted(hostId == null ? "" : "AND host_id = ?");

        Object[] args = hostId == null
            ? new Object[] { CH_DATE_TIME.format(from), CH_DATE_TIME.format(to) }
            : new Object[] { CH_DATE_TIME.format(from), CH_DATE_TIME.format(to), hostId };

        Map<String, Object> row = clickHouseJdbcTemplate.queryForMap(sql, args);

        return new DeveloperDashboardSeverityBreakdownResponse(
            Instant.now().toString(),
            period,
            from.toString(),
            to.toString(),
            asLong(row.get("critical_count")),
            asLong(row.get("high_count")),
            asLong(row.get("medium_count")),
            asLong(row.get("low_count")),
            asLong(row.get("total_failed")));
    }

    private List<DockerHostEntity> resolveHosts(Long hostId) {
        if (hostId != null) {
            return List.of(resolveHost(hostId));
        }
        return dockerHostRepository.findAll().stream()
            .filter(host -> host.isActive() && !host.isDeleted())
            .toList();
    }

    private DockerHostEntity resolveHost(Long hostId) {
        return dockerHostRepository.findByIdAndActiveTrueAndDeletedFalse(hostId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Активный Docker-хост не найден"));
    }

    private Statistics fetchStatsSnapshot(com.github.dockerjava.api.DockerClient client, String containerId) {
        AtomicReference<Statistics> ref = new AtomicReference<>();
        StatsCallback callback = new StatsCallback(ref);
        try {
            client.statsCmd(containerId)
                .withNoStream(true)
                .exec(callback);
            callback.awaitCompletion(2, TimeUnit.SECONDS);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        } finally {
            try {
                callback.close();
            } catch (IOException ignored) {
                // no-op
            }
        }
        return ref.get();
    }

    private double calculateCpuPercent(Statistics stats) {
        if (stats == null || stats.getCpuStats() == null || stats.getPreCpuStats() == null) {
            return 0.0d;
        }

        Long total = stats.getCpuStats().getCpuUsage() == null ? null : stats.getCpuStats().getCpuUsage().getTotalUsage();
        Long preTotal = stats.getPreCpuStats().getCpuUsage() == null ? null : stats.getPreCpuStats().getCpuUsage().getTotalUsage();
        Long system = stats.getCpuStats().getSystemCpuUsage();
        Long preSystem = stats.getPreCpuStats().getSystemCpuUsage();

        if (total == null || preTotal == null || system == null || preSystem == null) {
            return 0.0d;
        }

        long cpuDelta = total - preTotal;
        long systemDelta = system - preSystem;
        if (cpuDelta <= 0 || systemDelta <= 0) {
            return 0.0d;
        }

        long onlineCpus = stats.getCpuStats().getOnlineCpus() == null ? 1L : Math.max(1L, stats.getCpuStats().getOnlineCpus());
        return (cpuDelta * 100.0d * onlineCpus) / systemDelta;
    }

    private long readMemoryUsage(Statistics stats) {
        if (stats == null || stats.getMemoryStats() == null || stats.getMemoryStats().getUsage() == null) {
            return 0L;
        }
        return Math.max(0L, stats.getMemoryStats().getUsage());
    }

    private long readMemoryLimit(Statistics stats) {
        if (stats == null || stats.getMemoryStats() == null || stats.getMemoryStats().getLimit() == null) {
            return 0L;
        }
        return Math.max(0L, stats.getMemoryStats().getLimit());
    }

    private String extractContainerName(Container container) {
        if (container.getNames() != null && container.getNames().length > 0) {
            return container.getNames()[0].replaceFirst("^/", "");
        }
        String id = container.getId();
        if (id == null) {
            return "unknown";
        }
        return id.substring(0, Math.min(12, id.length()));
    }

    private String severityFromRank(int rank) {
        return switch (rank) {
            case 4 -> "CRITICAL";
            case 3 -> "HIGH";
            case 2 -> "MEDIUM";
            default -> "LOW";
        };
    }

    private int normalizeLimit(Integer limitRaw, int defaultValue, int maxValue) {
        if (limitRaw == null) {
            return defaultValue;
        }
        if (limitRaw < 1 || limitRaw > maxValue) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "limit должен быть в диапазоне 1.." + maxValue);
        }
        return limitRaw;
    }

    private long asLong(Object value) {
        if (value == null) {
            return 0L;
        }
        if (value instanceof Number n) {
            return n.longValue();
        }
        return Long.parseLong(value.toString());
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private String summarizeException(Exception ex) {
        String message = ex.getMessage();
        if (message == null || message.isBlank()) {
            return ex.getClass().getSimpleName();
        }
        return message;
    }

    private double round2(double value) {
        return Math.round(value * 100.0d) / 100.0d;
    }

    private Map<Long, String> loadHostNames() {
        Map<Long, String> map = new HashMap<>();
        for (DockerHostEntity host : dockerHostRepository.findAll()) {
            map.put(host.getId(), host.getName());
        }
        return map;
    }

    private static final class StatsCallback
            extends ResultCallbackTemplate<StatsCallback, Statistics> {

        private final AtomicReference<Statistics> ref;

        private StatsCallback(AtomicReference<Statistics> ref) {
            this.ref = ref;
        }

        @Override
        public void onNext(Statistics statistics) {
            ref.set(statistics);
            try {
                close();
            } catch (IOException ignored) {
                // no-op
            }
        }
    }
}

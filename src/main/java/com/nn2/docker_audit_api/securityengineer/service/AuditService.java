package com.nn2.docker_audit_api.securityengineer.service;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.DataAccessException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nn2.docker_audit_api.securityengineer.dto.AuditStatusResponse;
import com.nn2.docker_audit_api.securityengineer.dto.AuditStatusesPageResponse;
import com.nn2.docker_audit_api.securityengineer.dto.AuditViolationSummaryResponse;
import com.nn2.docker_audit_api.securityengineer.dto.ContainerCisAuditResponse;
import com.nn2.docker_audit_api.securityengineer.dto.CisRuleCheckResultResponse;
import com.nn2.docker_audit_api.securityengineer.entity.DockerHostEntity;
import com.nn2.docker_audit_api.securityengineer.entity.ScanEntity;
import com.nn2.docker_audit_api.developer.service.NotificationDispatcher;
import com.nn2.docker_audit_api.securityengineer.repository.DockerHostRepository;
import com.nn2.docker_audit_api.securityengineer.repository.ScanRepository;

@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final ScanRepository scanRepository;
    private final DockerHostRepository dockerHostRepository;
    private final CisRuleEngine cisRuleEngine;
    private final JdbcTemplate clickHouseJdbcTemplate;
    private final NotificationDispatcher notificationDispatcher;

    public AuditService(
            ScanRepository scanRepository,
            DockerHostRepository dockerHostRepository,
            CisRuleEngine cisRuleEngine,
            NotificationDispatcher notificationDispatcher,
            @Qualifier("clickHouseJdbcTemplate") JdbcTemplate clickHouseJdbcTemplate) {
        this.scanRepository = scanRepository;
        this.dockerHostRepository = dockerHostRepository;
        this.cisRuleEngine = cisRuleEngine;
        this.notificationDispatcher = notificationDispatcher;
        this.clickHouseJdbcTemplate = clickHouseJdbcTemplate;
    }

    @Transactional
    public ScanEntity createRunningScan(Long hostId, Long startedBy) {
        DockerHostEntity host = dockerHostRepository.findByIdAndActiveTrueAndDeletedFalse(hostId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Активный Docker-хост не найден"));

        ScanEntity scan = new ScanEntity();
        scan.setHostId(host.getId());
        scan.setStartedBy(startedBy);
        scan.setStartedAt(Instant.now());
        scan.setStatus("RUNNING");
        scan.setTotalContainers(0);
        scan.setTotalViolations(0);
        scan.setCriticalCount(0);
        scan.setHighCount(0);
        scan.setMediumCount(0);
        scan.setLowCount(0);
        return scanRepository.save(scan);
    }

    public AuditExecutionResult runAudit(Long hostId, Long startedBy) {
        ScanEntity runningScan = createRunningScan(hostId, startedBy);

        try {
            DockerHostEntity host = dockerHostRepository.findByIdAndActiveTrueAndDeletedFalse(hostId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Активный Docker-хост не найден"));

            List<ContainerCisAuditResponse> containerResults = cisRuleEngine.evaluateActiveRules(host.getBaseUrl());

            writeViolationsToClickHouse(runningScan.getId(), hostId, containerResults);
            ScanEntity completed = completeScan(runningScan.getId(), containerResults);
            return new AuditExecutionResult(completed, null);
        } catch (Exception ex) {
            log.error("Ошибка выполнения скана {}: {}", runningScan.getId(), ex.getMessage(), ex);
            ScanEntity failed = failScan(runningScan.getId());
            return new AuditExecutionResult(failed, ex.getMessage());
        }
    }

    public AuditStatusResponse getStatus(Long scanId) {
        ScanEntity scan = scanRepository.findById(scanId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Скан не найден"));

        return toStatus(scan);
    }

    public List<AuditStatusResponse> getRecentStatuses() {
        return scanRepository.findTop20ByOrderByStartedAtDesc().stream()
            .map(this::toStatus)
            .toList();
    }

    public AuditStatusesPageResponse searchStatuses(
            Integer page,
            Integer size,
            Long scanId,
            Long hostId,
            String status,
            String from,
            String to,
            String sortBy,
            String sortDir) {
        int safePage = normalizePage(page);
        int safeSize = normalizeSize(size);
        String safeSortBy = normalizeSortBy(sortBy);
        Sort.Direction direction = normalizeSortDirection(sortDir);

        if (scanId != null && scanId <= 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "scanId должен быть положительным");
        }

        if (hostId != null && hostId <= 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "hostId должен быть положительным");
        }

        Instant fromInstant = parseInstantOrNull(from, "from");
        Instant toInstant = parseInstantOrNull(to, "to");
        if (fromInstant != null && toInstant != null && !fromInstant.isBefore(toInstant)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Параметр from должен быть меньше to");
        }

        Specification<ScanEntity> spec = Specification.where(null);

        if (scanId != null) {
            spec = spec.and((root, query, cb) -> cb.equal(root.get("id"), scanId));
        }

        if (hostId != null) {
            spec = spec.and((root, query, cb) -> cb.equal(root.get("hostId"), hostId));
        }

        if (status != null && !status.isBlank()) {
            String normalized = status.trim().toUpperCase(Locale.ROOT);
            if (!normalized.equals("RUNNING") && !normalized.equals("COMPLETED") && !normalized.equals("FAILED")) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "status должен быть RUNNING, COMPLETED или FAILED");
            }
            spec = spec.and((root, query, cb) -> cb.equal(root.get("status"), normalized));
        }

        if (fromInstant != null) {
            spec = spec.and((root, query, cb) -> cb.greaterThanOrEqualTo(root.get("startedAt"), fromInstant));
        }

        if (toInstant != null) {
            spec = spec.and((root, query, cb) -> cb.lessThan(root.get("startedAt"), toInstant));
        }

        Pageable pageable = PageRequest.of(safePage, safeSize, Sort.by(direction, safeSortBy));
        Page<ScanEntity> result = scanRepository.findAll(spec, pageable);

        List<AuditStatusResponse> items = result.getContent().stream()
            .map(this::toStatus)
            .toList();

        return new AuditStatusesPageResponse(items, result.getTotalElements(), safePage, safeSize);
    }

    public AuditViolationSummaryResponse getSummary(Long scanId) {
        ScanEntity scan = scanRepository.findById(scanId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Скан не найден"));

        Integer totalFailed = Optional.ofNullable(scan.getTotalViolations()).orElse(0);
        Integer critical = Optional.ofNullable(scan.getCriticalCount()).orElse(0);
        Integer high = Optional.ofNullable(scan.getHighCount()).orElse(0);
        Integer medium = Optional.ofNullable(scan.getMediumCount()).orElse(0);
        Integer low = Optional.ofNullable(scan.getLowCount()).orElse(0);

        int totalChecks = totalFailed;
        Integer totalContainers = Optional.ofNullable(scan.getTotalContainers()).orElse(0);

        if (totalContainers > 0) {
            Integer totalRows = clickHouseJdbcTemplate.queryForObject(
                countRowsByScanSql(scanId),
                Integer.class);
            if (totalRows != null) {
                totalChecks = totalRows;
            }
        }

        return new AuditViolationSummaryResponse(
            scanId,
            totalChecks,
            totalFailed,
            critical,
            high,
            medium,
            low);
    }

    private void writeViolationsToClickHouse(Long scanId, Long hostId, List<ContainerCisAuditResponse> containerResults) {
        List<ViolationRow> rows = new ArrayList<>();
        for (ContainerCisAuditResponse container : containerResults) {
            for (CisRuleCheckResultResponse rule : container.rules()) {
                rows.add(new ViolationRow(
                    scanId,
                    container.containerId(),
                    container.containerName(),
                    hostId,
                    rule.cisCode(),
                    rule.name(),
                    rule.severity(),
                    rule.passed(),
                    rule.recommendation()));
            }
        }

        if (rows.isEmpty()) {
            return;
        }

        int insertedRows = 0;
        for (ViolationRow row : rows) {
            try {
                clickHouseJdbcTemplate.update(buildInsertSql(row));
                insertedRows++;
            } catch (DataAccessException ex) {
                log.error(
                    "Ошибка вставки строки в ClickHouse: scanId={}, containerId={}, ruleCode={}, insertedRows={}",
                    row.scanId(),
                    row.containerId(),
                    row.ruleCode(),
                    insertedRows,
                    ex);

                throw ex;
            }
        }
    }

    private String buildInsertSql(ViolationRow row) {
        return "INSERT INTO audit_analytics.violations_log "
            + "(scan_id, container_id, container_name, host_id, rule_code, rule_name, severity, passed, recommendation) VALUES ("
            + row.scanId() + ","
            + quote(row.containerId()) + ","
            + quote(row.containerName()) + ","
            + row.hostId() + ","
            + quote(row.ruleCode()) + ","
            + quote(row.ruleName()) + ","
            + quote(row.severity()) + ","
            + (row.passed() ? "1" : "0") + ","
            + quote(row.recommendation())
            + ")";
    }

    private String quote(String value) {
        if (value == null) {
            return "''";
        }
        String escaped = value
            .replace("'", "''")
            .replace("\n", " ")
            .replace("\r", " ");
        return "'" + escaped + "'";
    }

    private String countRowsByScanSql(Long scanId) {
        long safeScanId = scanId == null ? -1L : scanId;
        return "SELECT toInt32(count()) FROM audit_analytics.violations_log WHERE scan_id = " + safeScanId;
    }

    @Transactional
    protected ScanEntity completeScan(Long scanId, List<ContainerCisAuditResponse> containerResults) {
        ScanEntity scan = scanRepository.findById(scanId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Скан не найден"));

        int totalContainers = containerResults.size();
        int totalFailed = 0;
        Map<String, Integer> severityCounters = new java.util.HashMap<>();

        for (ContainerCisAuditResponse container : containerResults) {
            for (CisRuleCheckResultResponse rule : container.rules()) {
                if (!rule.passed()) {
                    totalFailed++;
                    String key = rule.severity() == null ? "LOW" : rule.severity().toUpperCase(Locale.ROOT);
                    severityCounters.put(key, severityCounters.getOrDefault(key, 0) + 1);
                }
            }
        }

        scan.setStatus("COMPLETED");
        scan.setFinishedAt(Instant.now());
        scan.setTotalContainers(totalContainers);
        scan.setTotalViolations(totalFailed);
        scan.setCriticalCount(severityCounters.getOrDefault("CRITICAL", 0));
        scan.setHighCount(severityCounters.getOrDefault("HIGH", 0));
        scan.setMediumCount(severityCounters.getOrDefault("MEDIUM", 0));
        scan.setLowCount(severityCounters.getOrDefault("LOW", 0));
        ScanEntity saved = scanRepository.save(scan);
        notificationDispatcher.dispatchForCompletedScan(saved);
        return saved;
    }

    @Transactional
    protected ScanEntity failScan(Long scanId) {
        ScanEntity scan = scanRepository.findById(scanId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Скан не найден"));
        scan.setStatus("FAILED");
        scan.setFinishedAt(Instant.now());
        return scanRepository.save(scan);
    }

    private AuditStatusResponse toStatus(ScanEntity scan) {
        return new AuditStatusResponse(
            scan.getId(),
            scan.getHostId(),
            scan.getStatus(),
            toIso(scan.getStartedAt()),
            toIso(scan.getFinishedAt()),
            Optional.ofNullable(scan.getTotalContainers()).orElse(0),
            Optional.ofNullable(scan.getTotalViolations()).orElse(0),
            Optional.ofNullable(scan.getCriticalCount()).orElse(0),
            Optional.ofNullable(scan.getHighCount()).orElse(0),
            Optional.ofNullable(scan.getMediumCount()).orElse(0),
            Optional.ofNullable(scan.getLowCount()).orElse(0));
    }

    private String toIso(Instant instant) {
        return instant == null ? null : Timestamp.from(instant).toInstant().toString();
    }

    private int normalizePage(Integer page) {
        if (page == null || page < 0) {
            return 0;
        }
        return page;
    }

    private int normalizeSize(Integer size) {
        if (size == null) {
            return 20;
        }
        if (size < 1 || size > 200) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "size должен быть в диапазоне 1..200");
        }
        return size;
    }

    private String normalizeSortBy(String sortBy) {
        if (sortBy == null || sortBy.isBlank()) {
            return "startedAt";
        }

        return switch (sortBy.trim()) {
            case "id", "hostId", "status", "startedAt", "finishedAt", "totalViolations" -> sortBy.trim();
            default -> throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "sortBy должен быть одним из: id, hostId, status, startedAt, finishedAt, totalViolations");
        };
    }

    private Sort.Direction normalizeSortDirection(String sortDir) {
        if (sortDir == null || sortDir.isBlank()) {
            return Sort.Direction.DESC;
        }
        try {
            return Sort.Direction.valueOf(sortDir.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "sortDir должен быть ASC или DESC");
        }
    }

    private Instant parseInstantOrNull(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Некорректный параметр " + fieldName + ": ожидается ISO-8601");
        }
    }

    private record ViolationRow(
        Long scanId,
        String containerId,
        String containerName,
        Long hostId,
        String ruleCode,
        String ruleName,
        String severity,
        boolean passed,
        String recommendation) {
    }

    public record AuditExecutionResult(ScanEntity scan, String errorMessage) {
    }
}

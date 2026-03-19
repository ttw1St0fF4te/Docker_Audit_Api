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
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nn2.docker_audit_api.securityengineer.dto.AuditStatusResponse;
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
        DockerHostEntity host = dockerHostRepository.findByIdAndActiveTrue(hostId)
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
            DockerHostEntity host = dockerHostRepository.findByIdAndActiveTrue(hostId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Активный Docker-хост не найден"));

            List<ContainerCisAuditResponse> containerResults = cisRuleEngine.evaluateActiveRules(host.getHostUrl());

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

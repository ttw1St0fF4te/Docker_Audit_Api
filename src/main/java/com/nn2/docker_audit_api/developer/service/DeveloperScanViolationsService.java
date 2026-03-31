package com.nn2.docker_audit_api.developer.service;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.nn2.docker_audit_api.developer.dto.DeveloperScanMetadataResponse;
import com.nn2.docker_audit_api.developer.dto.DeveloperScanViolationsResponse;
import com.nn2.docker_audit_api.developer.dto.DeveloperScanViolationsSummaryResponse;
import com.nn2.docker_audit_api.developer.dto.DeveloperViolationItemResponse;
import com.nn2.docker_audit_api.developer.repository.DeveloperNotificationRepository;
import com.nn2.docker_audit_api.securityengineer.entity.ScanEntity;
import com.nn2.docker_audit_api.securityengineer.repository.ScanRepository;

@Service
public class DeveloperScanViolationsService {

    private static final int DETAILS_RETENTION_DAYS = 30;

    private final DeveloperNotificationRepository developerNotificationRepository;
    private final ScanRepository scanRepository;
    private final JdbcTemplate clickHouseJdbcTemplate;

    public DeveloperScanViolationsService(
            DeveloperNotificationRepository developerNotificationRepository,
            ScanRepository scanRepository,
            @Qualifier("clickHouseJdbcTemplate") JdbcTemplate clickHouseJdbcTemplate) {
        this.developerNotificationRepository = developerNotificationRepository;
        this.scanRepository = scanRepository;
        this.clickHouseJdbcTemplate = clickHouseJdbcTemplate;
    }

    public DeveloperScanViolationsResponse getViolations(Long developerUserId, Long scanId) {
        ensureDeveloperOwnsScanNotification(developerUserId, scanId);

        ScanEntity scan = scanRepository.findById(scanId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Скан не найден"));

        List<DeveloperViolationItemResponse> violations = clickHouseJdbcTemplate.query(
            violationsByScanSql(scanId),
            (rs, rowNum) -> new DeveloperViolationItemResponse(
                rs.getLong("host_id"),
                "host-" + rs.getLong("host_id"),
                rs.getString("container_name"),
                rs.getString("rule_code"),
                rs.getString("rule_name"),
                normalizeSeverity(rs.getString("severity")),
                rs.getString("recommendation"),
                toIso(rs.getObject("timestamp"))));

        if (violations.isEmpty()) {
            return buildRetentionFallback(scan);
        }

        return new DeveloperScanViolationsResponse(
            scanId,
            true,
            DETAILS_RETENTION_DAYS,
            "Детали нарушений доступны",
            toScanMetadata(scan),
            buildSummaryFromViolations(violations),
            violations);
    }

    private void ensureDeveloperOwnsScanNotification(Long developerUserId, Long scanId) {
        boolean allowed = developerNotificationRepository.existsByDeveloperUserIdAndScanId(developerUserId, scanId);
        if (!allowed) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Уведомление по указанному scanId не найдено");
        }
    }

    private DeveloperScanViolationsResponse buildRetentionFallback(ScanEntity scan) {
        return new DeveloperScanViolationsResponse(
            scan.getId(),
            false,
            DETAILS_RETENTION_DAYS,
            "Детали скана недоступны: срок хранения в ClickHouse (30 дней) истек либо нарушений не было",
            toScanMetadata(scan),
            new DeveloperScanViolationsSummaryResponse(
                safe(scan.getTotalViolations()),
                safe(scan.getTotalContainers()),
                safe(scan.getCriticalCount()),
                safe(scan.getHighCount()),
                safe(scan.getMediumCount()),
                safe(scan.getLowCount())),
            List.of());
    }

    private DeveloperScanMetadataResponse toScanMetadata(ScanEntity scan) {
        return new DeveloperScanMetadataResponse(
            scan.getId(),
            scan.getHostId(),
            scan.getStatus(),
            toIso(scan.getStartedAt()),
            toIso(scan.getFinishedAt()),
            safe(scan.getTotalContainers()),
            safe(scan.getTotalViolations()),
            safe(scan.getCriticalCount()),
            safe(scan.getHighCount()),
            safe(scan.getMediumCount()),
            safe(scan.getLowCount()));
    }

    private DeveloperScanViolationsSummaryResponse buildSummaryFromViolations(List<DeveloperViolationItemResponse> violations) {
        int critical = 0;
        int high = 0;
        int medium = 0;
        int low = 0;
        Set<String> containers = new java.util.HashSet<>();

        for (DeveloperViolationItemResponse violation : violations) {
            String sev = normalizeSeverity(violation.severity());
            if ("CRITICAL".equals(sev)) {
                critical++;
            } else if ("HIGH".equals(sev)) {
                high++;
            } else if ("MEDIUM".equals(sev)) {
                medium++;
            } else {
                low++;
            }
            if (violation.container() != null && !violation.container().isBlank()) {
                containers.add(violation.container());
            }
        }

        return new DeveloperScanViolationsSummaryResponse(
            violations.size(),
            containers.size(),
            critical,
            high,
            medium,
            low);
    }

    private String violationsByScanSql(Long scanId) {
        long safeScanId = scanId == null ? -1L : scanId;
        return "SELECT host_id, container_name, rule_code, rule_name, severity, recommendation, timestamp "
            + "FROM audit_analytics.violations_log "
            + "WHERE scan_id = " + safeScanId + " AND passed = 0 "
            + "ORDER BY timestamp DESC";
    }

    private String normalizeSeverity(String severity) {
        if (severity == null || severity.isBlank()) {
            return "LOW";
        }
        return severity.trim().toUpperCase(Locale.ROOT);
    }

    private int safe(Integer value) {
        return value == null ? 0 : value;
    }

    private String toIso(Instant instant) {
        return instant == null ? null : instant.toString();
    }

    private String toIso(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Timestamp timestamp) {
            return timestamp.toInstant().toString();
        }
        if (value instanceof Instant instant) {
            return instant.toString();
        }
        return value.toString();
    }
}

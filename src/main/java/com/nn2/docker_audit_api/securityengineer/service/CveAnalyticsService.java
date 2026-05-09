package com.nn2.docker_audit_api.securityengineer.service;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.nn2.docker_audit_api.securityengineer.dto.analytics.AnalyticsOverviewResponse;
import com.nn2.docker_audit_api.securityengineer.dto.analytics.SecurityScoreTrendPointResponse;
import com.nn2.docker_audit_api.securityengineer.dto.analytics.SecurityScoreTrendResponse;
import com.nn2.docker_audit_api.securityengineer.dto.analytics.SeverityTrendPointResponse;
import com.nn2.docker_audit_api.securityengineer.dto.analytics.SeverityTrendResponse;
import com.nn2.docker_audit_api.securityengineer.dto.analytics.TopHostRiskItemResponse;
import com.nn2.docker_audit_api.securityengineer.dto.analytics.TopHostRiskResponse;
import com.nn2.docker_audit_api.securityengineer.dto.analytics.TopRuleItemResponse;
import com.nn2.docker_audit_api.securityengineer.dto.analytics.TopRulesResponse;
import com.nn2.docker_audit_api.securityengineer.entity.DockerHostEntity;
import com.nn2.docker_audit_api.securityengineer.entity.CveScanEntity;
import com.nn2.docker_audit_api.securityengineer.repository.CveScanRepository;
import com.nn2.docker_audit_api.securityengineer.repository.DockerHostRepository;

@Service
public class CveAnalyticsService {

    private static final DateTimeFormatter CH_DATE_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
        .withZone(ZoneOffset.UTC);

    private final JdbcTemplate clickHouseJdbcTemplate;
    private final DockerHostRepository dockerHostRepository;
    private final CveScanRepository cveScanRepository;

    public CveAnalyticsService(
            @Qualifier("clickHouseJdbcTemplate") JdbcTemplate clickHouseJdbcTemplate,
            DockerHostRepository dockerHostRepository,
            CveScanRepository cveScanRepository) {
        this.clickHouseJdbcTemplate = clickHouseJdbcTemplate;
        this.dockerHostRepository = dockerHostRepository;
        this.cveScanRepository = cveScanRepository;
    }

    public AnalyticsOverviewResponse getOverview(String fromRaw, String toRaw, Long hostId) {
        TimeRange range = resolveTimeRange(fromRaw, toRaw);
        validateHostId(hostId);
        long totalScans = cveScanRepository.countAllByRange(range.from(), range.to(), hostId);
        List<CveScanEntity> completedScans = loadCompletedScans(range, hostId);

        if (completedScans.isEmpty()) {
            return new AnalyticsOverviewResponse(totalScans, 0, 0, 0, 0, 0, 0, 100.0d);
        }

        long totalFailed = 0L;
        long critical = 0L;
        long high = 0L;
        long medium = 0L;
        long low = 0L;
        long unknown = 0L;
        for (CveScanEntity scan : completedScans) {
            totalFailed += safeInt(scan.getTotalVulnerabilities());
            critical += safeInt(scan.getCriticalCount());
            high += safeInt(scan.getHighCount());
            medium += safeInt(scan.getMediumCount());
            low += safeInt(scan.getLowCount());
            unknown += safeInt(scan.getUnknownCount());
        }

        double score = calculateWeightedScore(totalFailed, critical, high, medium, low, unknown);

        return new AnalyticsOverviewResponse(
            totalScans,
            totalFailed,
            totalFailed,
            critical,
            high,
            medium,
            low,
            score);
    }

    public SeverityTrendResponse getSeverityTrend(String fromRaw, String toRaw, String bucketRaw, Long hostId) {
        TimeRange range = resolveTimeRange(fromRaw, toRaw);
        String bucket = normalizeBucket(bucketRaw);
        validateHostId(hostId);
        List<CveScanEntity> completedScans = loadCompletedScans(range, hostId);

        if (completedScans.isEmpty()) {
            return new SeverityTrendResponse(List.of(), bucket, range.from().toString(), range.to().toString());
        }

        Map<String, SeverityAccumulator> buckets = new HashMap<>();
        for (CveScanEntity scan : completedScans) {
            String key = formatBucket(scan.getStartedAt(), bucket);
            SeverityAccumulator acc = buckets.computeIfAbsent(key, (ignored) -> new SeverityAccumulator());
            acc.critical += safeInt(scan.getCriticalCount());
            acc.high += safeInt(scan.getHighCount());
            acc.medium += safeInt(scan.getMediumCount());
            acc.low += safeInt(scan.getLowCount());
            acc.total += safeInt(scan.getTotalVulnerabilities());
        }

        List<SeverityTrendPointResponse> items = buckets.entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .map(entry -> new SeverityTrendPointResponse(
                entry.getKey(),
                entry.getValue().critical,
                entry.getValue().high,
                entry.getValue().medium,
                entry.getValue().low,
                entry.getValue().total))
            .toList();

        return new SeverityTrendResponse(items, bucket, range.from().toString(), range.to().toString());
    }

    public SecurityScoreTrendResponse getSecurityScoreTrend(String fromRaw, String toRaw, String bucketRaw, Long hostId) {
        TimeRange range = resolveTimeRange(fromRaw, toRaw);
        String bucket = normalizeBucket(bucketRaw);
        validateHostId(hostId);
        List<CveScanEntity> completedScans = loadCompletedScans(range, hostId);

        if (completedScans.isEmpty()) {
            return new SecurityScoreTrendResponse(List.of(), bucket, range.from().toString(), range.to().toString());
        }

        Map<String, ScoreAccumulator> buckets = new HashMap<>();
        for (CveScanEntity scan : completedScans) {
            String key = formatBucket(scan.getStartedAt(), bucket);
            ScoreAccumulator acc = buckets.computeIfAbsent(key, (ignored) -> new ScoreAccumulator());
            acc.total += safeInt(scan.getTotalVulnerabilities());
            acc.critical += safeInt(scan.getCriticalCount());
            acc.high += safeInt(scan.getHighCount());
            acc.medium += safeInt(scan.getMediumCount());
            acc.low += safeInt(scan.getLowCount());
            acc.unknown += safeInt(scan.getUnknownCount());
        }

        List<SecurityScoreTrendPointResponse> items = buckets.entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .map(entry -> {
                ScoreAccumulator acc = entry.getValue();
                double score = calculateWeightedScore(acc.total, acc.critical, acc.high, acc.medium, acc.low, acc.unknown);
                return new SecurityScoreTrendPointResponse(entry.getKey(), score, acc.total, acc.total);
            })
            .toList();

        return new SecurityScoreTrendResponse(items, bucket, range.from().toString(), range.to().toString());
    }

    public TopHostRiskResponse getTopHosts(String fromRaw, String toRaw, Integer limitRaw) {
        TimeRange range = resolveTimeRange(fromRaw, toRaw);
        int limit = normalizeLimit(limitRaw, 10, 50);
        List<CveScanEntity> completedScans = loadCompletedScans(range, null);

        if (completedScans.isEmpty()) {
            return new TopHostRiskResponse(List.of(), range.from().toString(), range.to().toString(), limit);
        }

        Map<Long, HostAccumulator> hosts = new HashMap<>();
        for (CveScanEntity scan : completedScans) {
            HostAccumulator acc = hosts.computeIfAbsent(scan.getHostId(), (ignored) -> new HostAccumulator());
            acc.scans += 1;
            acc.total += safeInt(scan.getTotalVulnerabilities());
            acc.critical += safeInt(scan.getCriticalCount());
            acc.high += safeInt(scan.getHighCount());
            acc.medium += safeInt(scan.getMediumCount());
            acc.low += safeInt(scan.getLowCount());
            acc.unknown += safeInt(scan.getUnknownCount());
        }

        Map<Long, String> hostNames = loadHostNames();

        List<TopHostRiskItemResponse> items = hosts.entrySet().stream()
            .map(entry -> {
                HostAccumulator acc = entry.getValue();
                double score = calculateWeightedScore(acc.total, acc.critical, acc.high, acc.medium, acc.low, acc.unknown);
                Long hostId = entry.getKey();
                return new TopHostRiskItemResponse(
                    hostId,
                    hostNames.getOrDefault(hostId, "host-" + hostId),
                    acc.scans,
                    acc.total,
                    acc.critical,
                    acc.high,
                    acc.medium,
                    acc.low,
                    score);
            })
            .sorted((a, b) -> Long.compare(b.totalFailed(), a.totalFailed()))
            .limit(limit)
            .toList();

        return new TopHostRiskResponse(items, range.from().toString(), range.to().toString(), limit);
    }

    public TopRulesResponse getTopRules(String fromRaw, String toRaw, Integer limitRaw, Long hostId) {
        TimeRange range = resolveTimeRange(fromRaw, toRaw);
        int limit = normalizeLimit(limitRaw, 10, 100);
        validateHostId(hostId);
        List<Long> completedScanIds = loadCompletedScanIds(range, hostId);

        if (completedScanIds.isEmpty()) {
            return new TopRulesResponse(List.of(), range.from().toString(), range.to().toString(), limit);
        }

        String sql = """
            SELECT
                vulnerability_id AS rule_code,
                any(vulnerability_title) AS rule_name,
                toInt64(count()) AS failed_count,
                toInt64(uniqExact(scan_id)) AS affected_scans,
                toInt64(uniqExact(image_name)) AS affected_containers
            FROM audit_analytics.cve_vulnerabilities_log
            WHERE scan_id IN (%s)
            GROUP BY vulnerability_id
            ORDER BY failed_count DESC, affected_scans DESC
            LIMIT %d
            """.formatted(toInClause(completedScanIds), limit);

        List<Map<String, Object>> rows = clickHouseJdbcTemplate.queryForList(sql);

        List<TopRuleItemResponse> items = rows.stream()
            .map(row -> new TopRuleItemResponse(
                asString(row.get("rule_code")),
                asString(row.get("rule_name")),
                asLong(row.get("failed_count")),
                asLong(row.get("affected_scans")),
                asLong(row.get("affected_containers"))))
            .toList();

        return new TopRulesResponse(items, range.from().toString(), range.to().toString(), limit);
    }

    private Object[] buildQueryArgs(TimeRange range) {
        List<Object> args = new ArrayList<>();
        args.add(CH_DATE_TIME.format(range.from()));
        args.add(CH_DATE_TIME.format(range.to()));
        return args.toArray();
    }

    private List<Long> loadCompletedScanIds(TimeRange range, Long hostId) {
        return cveScanRepository.findCompletedScanIdsByRange(range.from(), range.to(), hostId);
    }

    private List<CveScanEntity> loadCompletedScans(TimeRange range, Long hostId) {
        return cveScanRepository.findCompletedScansByRange(range.from(), range.to(), hostId);
    }

    private String toInClause(List<Long> ids) {
        return ids.stream().map(String::valueOf).collect(Collectors.joining(","));
    }

    private TimeRange resolveTimeRange(String fromRaw, String toRaw) {
        Instant to = toRaw == null || toRaw.isBlank() ? Instant.now() : parseInstant(toRaw, "to");
        Instant from = fromRaw == null || fromRaw.isBlank() ? to.minus(7, ChronoUnit.DAYS) : parseInstant(fromRaw, "from");

        if (!from.isBefore(to)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Параметр from должен быть меньше to");
        }

        if (ChronoUnit.DAYS.between(from, to) > 365) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Период не должен превышать 365 дней");
        }

        return new TimeRange(from, to);
    }

    private Instant parseInstant(String value, String fieldName) {
        try {
            return Instant.parse(value);
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Некорректный параметр " + fieldName + ": ожидается ISO-8601");
        }
    }

    private String normalizeBucket(String bucketRaw) {
        String bucket = bucketRaw == null || bucketRaw.isBlank() ? "DAY" : bucketRaw.trim().toUpperCase(Locale.ROOT);
        if (!bucket.equals("HOUR") && !bucket.equals("DAY")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "bucket должен быть HOUR или DAY");
        }
        return bucket;
    }

    private String bucketExpression(String bucket) {
        return bucket.equals("HOUR")
            ? "formatDateTime(toStartOfHour(scan_timestamp), '%Y-%m-%dT%H:00:00Z')"
            : "formatDateTime(toStartOfDay(scan_timestamp), '%Y-%m-%dT00:00:00Z')";
    }

    private String formatBucket(Instant instant, String bucket) {
        Instant normalized = bucket.equals("HOUR")
            ? instant.truncatedTo(ChronoUnit.HOURS)
            : instant.truncatedTo(ChronoUnit.DAYS);
        return DateTimeFormatter.ISO_INSTANT.format(normalized);
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

    private void validateHostId(Long hostId) {
        if (hostId != null && hostId <= 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "hostId должен быть положительным");
        }
    }

    private Map<Long, String> loadHostNames() {
        List<DockerHostEntity> hosts = dockerHostRepository.findAll();
        Map<Long, String> byId = new HashMap<>();
        for (DockerHostEntity host : hosts) {
            byId.put(host.getId(), host.getName());
        }
        return byId;
    }

    private long asLong(Object value) {
        if (value == null) {
            return 0L;
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        return Long.parseLong(value.toString());
    }

    private double asDouble(Object value) {
        if (value == null) {
            return 0.0d;
        }
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        return Double.parseDouble(value.toString());
    }

    private String asString(Object value) {
        return value == null ? null : value.toString();
    }

    private static class SeverityAccumulator {
        long critical;
        long high;
        long medium;
        long low;
        long total;
    }

    private static class ScoreAccumulator {
        long total;
        long critical;
        long high;
        long medium;
        long low;
        long unknown;
    }

    private static class HostAccumulator {
        long scans;
        long total;
        long critical;
        long high;
        long medium;
        long low;
        long unknown;
    }

    private long safeInt(Integer value) {
        return value == null ? 0L : value;
    }

    private double calculateWeightedScore(long totalFailed, long critical, long high, long medium, long low, long unknown) {
        if (totalFailed <= 0) {
            return 100.0d;
        }
        double weighted = critical * 10.0 + high * 5.0 + medium * 3.0 + low + unknown;
        double max = totalFailed * 10.0;
        return Math.max(0.0d, Math.min(100.0d, Math.round((100.0d - (weighted * 100.0d / max)) * 100.0d) / 100.0d));
    }

    private record TimeRange(Instant from, Instant to) {
    }
}

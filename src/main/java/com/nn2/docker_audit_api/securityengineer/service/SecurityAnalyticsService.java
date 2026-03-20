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
import com.nn2.docker_audit_api.securityengineer.repository.DockerHostRepository;

@Service
public class SecurityAnalyticsService {

    private static final DateTimeFormatter CH_DATE_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
        .withZone(ZoneOffset.UTC);

    private final JdbcTemplate clickHouseJdbcTemplate;
    private final DockerHostRepository dockerHostRepository;

    public SecurityAnalyticsService(
            @Qualifier("clickHouseJdbcTemplate") JdbcTemplate clickHouseJdbcTemplate,
            DockerHostRepository dockerHostRepository) {
        this.clickHouseJdbcTemplate = clickHouseJdbcTemplate;
        this.dockerHostRepository = dockerHostRepository;
    }

    public AnalyticsOverviewResponse getOverview(String fromRaw, String toRaw, Long hostId) {
        TimeRange range = resolveTimeRange(fromRaw, toRaw);
        validateHostId(hostId);

        String sql = """
            SELECT
                toInt64(uniqExact(scan_id)) AS total_scans,
                toInt64(count()) AS total_checks,
                toInt64(sumIf(1, passed = 0)) AS total_failed,
                toInt64(sumIf(1, passed = 0 AND severity = 'CRITICAL')) AS critical_count,
                toInt64(sumIf(1, passed = 0 AND severity = 'HIGH')) AS high_count,
                toInt64(sumIf(1, passed = 0 AND severity = 'MEDIUM')) AS medium_count,
                toInt64(sumIf(1, passed = 0 AND severity = 'LOW')) AS low_count,
                round(100.0 - (sumIf(1, passed = 0) * 100.0 / nullIf(count(), 0)), 2) AS security_score
            FROM audit_analytics.violations_log
            WHERE timestamp >= toDateTime(?)
              AND timestamp < toDateTime(?)
            """ + hostFilterClause(hostId);

                Map<String, Object> row = clickHouseJdbcTemplate.queryForMap(sql, buildQueryArgs(range, hostId));

        return new AnalyticsOverviewResponse(
            asLong(row.get("total_scans")),
            asLong(row.get("total_checks")),
            asLong(row.get("total_failed")),
            asLong(row.get("critical_count")),
            asLong(row.get("high_count")),
            asLong(row.get("medium_count")),
            asLong(row.get("low_count")),
            asDouble(row.get("security_score")));
    }

    public SeverityTrendResponse getSeverityTrend(String fromRaw, String toRaw, String bucketRaw, Long hostId) {
        TimeRange range = resolveTimeRange(fromRaw, toRaw);
        String bucket = normalizeBucket(bucketRaw);
        validateHostId(hostId);

        String bucketExpr = bucketExpression(bucket);
        String sql = """
            SELECT
                %s AS bucket_start,
                toInt64(sumIf(1, passed = 0 AND severity = 'CRITICAL')) AS critical_count,
                toInt64(sumIf(1, passed = 0 AND severity = 'HIGH')) AS high_count,
                toInt64(sumIf(1, passed = 0 AND severity = 'MEDIUM')) AS medium_count,
                toInt64(sumIf(1, passed = 0 AND severity = 'LOW')) AS low_count,
                toInt64(sumIf(1, passed = 0)) AS total_failed
            FROM audit_analytics.violations_log
            WHERE timestamp >= toDateTime(?)
              AND timestamp < toDateTime(?)
              %s
            GROUP BY bucket_start
            ORDER BY bucket_start ASC
            """.formatted(bucketExpr, hostFilterClauseWithAnd(hostId));

        List<Map<String, Object>> rows = clickHouseJdbcTemplate.queryForList(
            sql,
            buildQueryArgs(range, hostId));

        List<SeverityTrendPointResponse> items = rows.stream()
            .map(row -> new SeverityTrendPointResponse(
                asString(row.get("bucket_start")),
                asLong(row.get("critical_count")),
                asLong(row.get("high_count")),
                asLong(row.get("medium_count")),
                asLong(row.get("low_count")),
                asLong(row.get("total_failed"))))
            .toList();

        return new SeverityTrendResponse(items, bucket, range.from().toString(), range.to().toString());
    }

    public SecurityScoreTrendResponse getSecurityScoreTrend(String fromRaw, String toRaw, String bucketRaw, Long hostId) {
        TimeRange range = resolveTimeRange(fromRaw, toRaw);
        String bucket = normalizeBucket(bucketRaw);
        validateHostId(hostId);

        String bucketExpr = bucketExpression(bucket);
        String sql = """
            SELECT
                %s AS bucket_start,
                toInt64(count()) AS total_checks,
                toInt64(sumIf(1, passed = 0)) AS total_failed,
                round(100.0 - (sumIf(1, passed = 0) * 100.0 / nullIf(count(), 0)), 2) AS security_score
            FROM audit_analytics.violations_log
            WHERE timestamp >= toDateTime(?)
              AND timestamp < toDateTime(?)
              %s
            GROUP BY bucket_start
            ORDER BY bucket_start ASC
            """.formatted(bucketExpr, hostFilterClauseWithAnd(hostId));

        List<Map<String, Object>> rows = clickHouseJdbcTemplate.queryForList(
            sql,
            buildQueryArgs(range, hostId));

        List<SecurityScoreTrendPointResponse> items = rows.stream()
            .map(row -> new SecurityScoreTrendPointResponse(
                asString(row.get("bucket_start")),
                asDouble(row.get("security_score")),
                asLong(row.get("total_checks")),
                asLong(row.get("total_failed"))))
            .toList();

        return new SecurityScoreTrendResponse(items, bucket, range.from().toString(), range.to().toString());
    }

    public TopHostRiskResponse getTopHosts(String fromRaw, String toRaw, Integer limitRaw) {
        TimeRange range = resolveTimeRange(fromRaw, toRaw);
        int limit = normalizeLimit(limitRaw, 10, 50);

        String sql = """
            SELECT
                toInt64(host_id) AS host_id,
                toInt64(uniqExact(scan_id)) AS scans,
                toInt64(sumIf(1, passed = 0)) AS total_failed,
                toInt64(sumIf(1, passed = 0 AND severity = 'CRITICAL')) AS critical_count,
                toInt64(sumIf(1, passed = 0 AND severity = 'HIGH')) AS high_count,
                toInt64(sumIf(1, passed = 0 AND severity = 'MEDIUM')) AS medium_count,
                toInt64(sumIf(1, passed = 0 AND severity = 'LOW')) AS low_count,
                round(100.0 - (sumIf(1, passed = 0) * 100.0 / nullIf(count(), 0)), 2) AS security_score
            FROM audit_analytics.violations_log
            WHERE timestamp >= toDateTime(?)
              AND timestamp < toDateTime(?)
            GROUP BY host_id
            ORDER BY total_failed DESC, critical_count DESC, high_count DESC
            LIMIT %d
            """.formatted(limit);

        List<Map<String, Object>> rows = clickHouseJdbcTemplate.queryForList(
            sql,
            CH_DATE_TIME.format(range.from()),
            CH_DATE_TIME.format(range.to()));

        Map<Long, String> hostNames = loadHostNames();

        List<TopHostRiskItemResponse> items = rows.stream()
            .map(row -> {
                Long hostId = asLong(row.get("host_id"));
                return new TopHostRiskItemResponse(
                    hostId,
                    hostNames.getOrDefault(hostId, "host-" + hostId),
                    asLong(row.get("scans")),
                    asLong(row.get("total_failed")),
                    asLong(row.get("critical_count")),
                    asLong(row.get("high_count")),
                    asLong(row.get("medium_count")),
                    asLong(row.get("low_count")),
                    asDouble(row.get("security_score")));
            })
            .toList();

        return new TopHostRiskResponse(items, range.from().toString(), range.to().toString(), limit);
    }

    public TopRulesResponse getTopRules(String fromRaw, String toRaw, Integer limitRaw, Long hostId) {
        TimeRange range = resolveTimeRange(fromRaw, toRaw);
        int limit = normalizeLimit(limitRaw, 10, 100);
        validateHostId(hostId);

        String sql = """
            SELECT
                rule_code,
                any(rule_name) AS rule_name,
                toInt64(sumIf(1, passed = 0)) AS failed_count,
                toInt64(uniqExactIf(scan_id, passed = 0)) AS affected_scans,
                toInt64(uniqExactIf(container_id, passed = 0)) AS affected_containers
            FROM audit_analytics.violations_log
            WHERE timestamp >= toDateTime(?)
              AND timestamp < toDateTime(?)
              %s
            GROUP BY rule_code
            HAVING failed_count > 0
            ORDER BY failed_count DESC, affected_scans DESC
            LIMIT %d
            """.formatted(hostFilterClauseWithAnd(hostId), limit);

        List<Map<String, Object>> rows = clickHouseJdbcTemplate.queryForList(
            sql,
            buildQueryArgs(range, hostId));

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

    private String hostFilterClause(Long hostId) {
        return hostId == null ? "" : " AND host_id = ?";
    }

    private String hostFilterClauseWithAnd(Long hostId) {
        return hostId == null ? "" : "AND host_id = ?";
    }

    private Object[] buildQueryArgs(TimeRange range, Long hostId) {
        List<Object> args = new ArrayList<>();
        args.add(CH_DATE_TIME.format(range.from()));
        args.add(CH_DATE_TIME.format(range.to()));
        if (hostId != null) {
            args.add(hostId);
        }
        return args.toArray();
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
            ? "formatDateTime(toStartOfHour(timestamp), '%Y-%m-%dT%H:00:00Z')"
            : "formatDateTime(toStartOfDay(timestamp), '%Y-%m-%dT00:00:00Z')";
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

    private record TimeRange(Instant from, Instant to) {
    }
}

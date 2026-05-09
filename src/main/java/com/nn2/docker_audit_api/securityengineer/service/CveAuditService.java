package com.nn2.docker_audit_api.securityengineer.service;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.nn2.docker_audit_api.securityengineer.dto.CveAuditStatusResponse;
import com.nn2.docker_audit_api.securityengineer.dto.CveAuditStatusesPageResponse;
import com.nn2.docker_audit_api.securityengineer.dto.CveViolationSummaryResponse;
import com.nn2.docker_audit_api.securityengineer.entity.CveScanEntity;
import com.nn2.docker_audit_api.securityengineer.repository.CveScanRepository;

@Service
public class CveAuditService {

    private final CveScanRepository cveScanRepository;

    public CveAuditService(CveScanRepository cveScanRepository) {
        this.cveScanRepository = cveScanRepository;
    }

    public CveAuditStatusesPageResponse searchStatuses(
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

        Specification<CveScanEntity> spec = Specification.where(null);

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
        Page<CveScanEntity> result = cveScanRepository.findAll(spec, pageable);

        List<CveAuditStatusResponse> items = result.getContent().stream()
            .map(this::toStatus)
            .toList();

        return new CveAuditStatusesPageResponse(items, result.getTotalElements(), safePage, safeSize);
    }

    public CveViolationSummaryResponse getSummary(Long scanId) {
        CveScanEntity scan = cveScanRepository.findById(scanId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "CVE-скан не найден"));

        Integer totalFailed = Optional.ofNullable(scan.getTotalVulnerabilities()).orElse(0);
        Integer critical = Optional.ofNullable(scan.getCriticalCount()).orElse(0);
        Integer high = Optional.ofNullable(scan.getHighCount()).orElse(0);
        Integer medium = Optional.ofNullable(scan.getMediumCount()).orElse(0);
        Integer low = Optional.ofNullable(scan.getLowCount()).orElse(0);
        Integer unknown = Optional.ofNullable(scan.getUnknownCount()).orElse(0);

        return new CveViolationSummaryResponse(
            scanId,
            totalFailed,
            totalFailed,
            critical,
            high,
            medium,
            low,
            unknown);
    }

    private CveAuditStatusResponse toStatus(CveScanEntity scan) {
        return new CveAuditStatusResponse(
            scan.getId(),
            scan.getHostId(),
            scan.getStatus(),
            toIso(scan.getStartedAt()),
            toIso(scan.getFinishedAt()),
            Optional.ofNullable(scan.getTotalImages()).orElse(0),
            Optional.ofNullable(scan.getTotalVulnerabilities()).orElse(0),
            Optional.ofNullable(scan.getCriticalCount()).orElse(0),
            Optional.ofNullable(scan.getHighCount()).orElse(0),
            Optional.ofNullable(scan.getMediumCount()).orElse(0),
            Optional.ofNullable(scan.getLowCount()).orElse(0),
            Optional.ofNullable(scan.getUnknownCount()).orElse(0));
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

        String normalized = sortBy.trim();
        if (normalized.equals("totalViolations")) {
            return "totalVulnerabilities";
        }

        return switch (normalized) {
            case "id", "hostId", "status", "startedAt", "finishedAt", "totalVulnerabilities" -> normalized;
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
}

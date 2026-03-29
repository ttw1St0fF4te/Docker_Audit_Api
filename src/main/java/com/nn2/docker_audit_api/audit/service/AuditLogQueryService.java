package com.nn2.docker_audit_api.audit.service;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.nn2.docker_audit_api.audit.dto.AuditChangeLogItemResponse;
import com.nn2.docker_audit_api.audit.dto.AuditChangeLogPageResponse;
import com.nn2.docker_audit_api.audit.entity.AuditChangeLogEntity;
import com.nn2.docker_audit_api.audit.repository.AuditChangeLogRepository;

@Service
public class AuditLogQueryService {

    private static final int DEFAULT_PAGE = 0;
    private static final int DEFAULT_SIZE = 20;
    private static final int MAX_SIZE = 200;
    private static final int DEFAULT_EXPORT_LIMIT = 5000;
    private static final int MAX_EXPORT_LIMIT = 20000;
    private static final DateTimeFormatter FILE_TS = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
        .withZone(ZoneId.systemDefault());

    private final AuditChangeLogRepository auditChangeLogRepository;

    public AuditLogQueryService(AuditChangeLogRepository auditChangeLogRepository) {
        this.auditChangeLogRepository = auditChangeLogRepository;
    }

    public AuditChangeLogPageResponse search(
            Integer page,
            Integer size,
            String tableName,
            String operation,
            String changedBy,
            String requestId,
            String from,
            String to) {
        int safePage = normalizePage(page);
        int safeSize = normalizeSize(size);

        Instant fromInstant = parseInstantOrNull(from, "from");
        Instant toInstant = parseInstantOrNull(to, "to");
        validateRange(fromInstant, toInstant);

        Specification<AuditChangeLogEntity> specification = buildSpecification(
            tableName,
            operation,
            changedBy,
            requestId,
            fromInstant,
            toInstant);

        Pageable pageable = PageRequest.of(safePage, safeSize, Sort.by(Sort.Direction.DESC, "changedAt"));
        Page<AuditChangeLogEntity> result = auditChangeLogRepository.findAll(specification, pageable);

        List<AuditChangeLogItemResponse> items = result.getContent().stream()
            .map(this::toResponse)
            .toList();

        return new AuditChangeLogPageResponse(items, result.getTotalElements(), safePage, safeSize);
    }

    public List<String> listTableNames() {
        return auditChangeLogRepository.findDistinctTableNames();
    }

    public byte[] exportCsv(
            Integer limit,
            String tableName,
            String operation,
            String changedBy,
            String requestId,
            String from,
            String to) {
        int safeLimit = normalizeExportLimit(limit);

        Instant fromInstant = parseInstantOrNull(from, "from");
        Instant toInstant = parseInstantOrNull(to, "to");
        validateRange(fromInstant, toInstant);

        Specification<AuditChangeLogEntity> specification = buildSpecification(
            tableName,
            operation,
            changedBy,
            requestId,
            fromInstant,
            toInstant);

        Pageable pageable = PageRequest.of(0, safeLimit, Sort.by(Sort.Direction.DESC, "changedAt"));
        List<AuditChangeLogEntity> rows = auditChangeLogRepository.findAll(specification, pageable).getContent();

        String header = "id,table_name,operation,record_pk,changed_by,changed_at,request_id,before_json,after_json\n";
        String body = rows.stream()
            .map(this::toCsvRow)
            .collect(Collectors.joining("\n"));

        String csv = body.isEmpty() ? header : header + body + "\n";
        byte[] content = csv.getBytes(StandardCharsets.UTF_8);
        saveCsvToDesktop(content);
        return content;
    }

    private void saveCsvToDesktop(byte[] content) {
        Path desktopDir = Path.of(System.getProperty("user.home"), "Desktop", "audit-action-reports");
        try {
            Files.createDirectories(desktopDir);

            String timestamp = FILE_TS.format(Instant.now());
            String fileName = "audit-change-log-" + timestamp + ".csv";
            Path targetPath = desktopDir.resolve(fileName);

            Files.write(targetPath, content);
        } catch (IOException ex) {
            throw new ResponseStatusException(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Не удалось сохранить CSV-отчет аудита на рабочий стол");
        }
    }

    private Specification<AuditChangeLogEntity> buildSpecification(
            String tableName,
            String operation,
            String changedBy,
            String requestId,
            Instant from,
            Instant to) {
        Specification<AuditChangeLogEntity> specification = Specification.where(null);

        if (tableName != null && !tableName.isBlank()) {
            String normalized = tableName.trim().toLowerCase(Locale.ROOT);
            specification = specification.and((root, query, cb) ->
                cb.equal(cb.lower(root.get("tableName")), normalized));
        }

        if (operation != null && !operation.isBlank()) {
            String normalizedOperation = operation.trim().toUpperCase(Locale.ROOT);
            validateOperation(normalizedOperation);
            specification = specification.and((root, query, cb) -> cb.equal(root.get("operation"), normalizedOperation));
        }

        if (changedBy != null && !changedBy.isBlank()) {
            String normalizedUser = "%" + changedBy.trim().toLowerCase(Locale.ROOT) + "%";
            specification = specification.and((root, query, cb) ->
                cb.like(cb.lower(root.get("changedBy")), normalizedUser));
        }

        if (requestId != null && !requestId.isBlank()) {
            String normalizedRequestId = requestId.trim();
            specification = specification.and((root, query, cb) -> cb.equal(root.get("requestId"), normalizedRequestId));
        }

        if (from != null) {
            specification = specification.and((root, query, cb) -> cb.greaterThanOrEqualTo(root.get("changedAt"), from));
        }

        if (to != null) {
            specification = specification.and((root, query, cb) -> cb.lessThan(root.get("changedAt"), to));
        }

        return specification;
    }

    private AuditChangeLogItemResponse toResponse(AuditChangeLogEntity entity) {
        return new AuditChangeLogItemResponse(
            entity.getId(),
            entity.getTableName(),
            entity.getOperation(),
            entity.getRecordPk(),
            entity.getChangedBy(),
            toIso(entity.getChangedAt()),
            entity.getBeforeJson(),
            entity.getAfterJson(),
            entity.getRequestId());
    }

    private String toCsvRow(AuditChangeLogEntity entity) {
        return String.join(",",
            csv(entity.getId()),
            csv(entity.getTableName()),
            csv(entity.getOperation()),
            csv(entity.getRecordPk()),
            csv(entity.getChangedBy()),
            csv(toIso(entity.getChangedAt())),
            csv(entity.getRequestId()),
            csv(entity.getBeforeJson()),
            csv(entity.getAfterJson()));
    }

    private String csv(Object value) {
        if (value == null) {
            return "";
        }

        String raw = String.valueOf(value);
        String escaped = raw.replace("\"", "\"\"");
        return "\"" + escaped + "\"";
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

    private int normalizeExportLimit(Integer limit) {
        if (limit == null) {
            return DEFAULT_EXPORT_LIMIT;
        }
        if (limit < 1 || limit > MAX_EXPORT_LIMIT) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "limit должен быть в диапазоне 1.." + MAX_EXPORT_LIMIT);
        }
        return limit;
    }

    private Instant parseInstantOrNull(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Некорректный формат " + fieldName + ". Используйте ISO-8601");
        }
    }

    private void validateRange(Instant from, Instant to) {
        if (from != null && to != null && !from.isBefore(to)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Параметр from должен быть меньше to");
        }
    }

    private void validateOperation(String operation) {
        if (!"INSERT".equals(operation) && !"UPDATE".equals(operation) && !"DELETE".equals(operation)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "operation должен быть INSERT, UPDATE или DELETE");
        }
    }

    private String toIso(Instant instant) {
        return instant == null ? null : instant.toString();
    }
}

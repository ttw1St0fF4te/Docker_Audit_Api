package com.nn2.docker_audit_api.controller;

import java.nio.charset.StandardCharsets;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.nn2.docker_audit_api.audit.dto.AuditChangeLogPageResponse;
import com.nn2.docker_audit_api.audit.service.AuditLogQueryService;

@Validated
@RestController
@RequestMapping("/api/admin/audit-logs")
public class AdminAuditLogController {

    private final AuditLogQueryService auditLogQueryService;

    public AdminAuditLogController(AuditLogQueryService auditLogQueryService) {
        this.auditLogQueryService = auditLogQueryService;
    }

    @GetMapping
    public AuditChangeLogPageResponse listLogs(
            @RequestParam(name = "page", required = false) Integer page,
            @RequestParam(name = "size", required = false) Integer size,
            @RequestParam(name = "tableName", required = false) String tableName,
            @RequestParam(name = "operation", required = false) String operation,
            @RequestParam(name = "changedBy", required = false) String changedBy,
            @RequestParam(name = "from", required = false) String from,
            @RequestParam(name = "to", required = false) String to) {
        return auditLogQueryService.search(page, size, tableName, operation, changedBy, from, to);
    }

    @GetMapping(value = "/export", produces = "text/csv")
    public ResponseEntity<byte[]> exportLogs(
            @RequestParam(name = "limit", required = false) Integer limit,
            @RequestParam(name = "tableName", required = false) String tableName,
            @RequestParam(name = "operation", required = false) String operation,
            @RequestParam(name = "changedBy", required = false) String changedBy,
            @RequestParam(name = "from", required = false) String from,
            @RequestParam(name = "to", required = false) String to) {
        byte[] content = auditLogQueryService.exportCsv(limit, tableName, operation, changedBy, from, to);

        return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=audit-change-log.csv")
            .contentType(new MediaType("text", "csv", StandardCharsets.UTF_8))
            .body(content);
    }
}

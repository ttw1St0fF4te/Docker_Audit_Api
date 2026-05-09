package com.nn2.docker_audit_api.controller;

import java.time.Instant;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.nn2.docker_audit_api.auth.jwt.JwtPrincipal;
import com.nn2.docker_audit_api.securityengineer.dto.AuditRunRequest;
import com.nn2.docker_audit_api.securityengineer.dto.CveAuditStatusesPageResponse;
import com.nn2.docker_audit_api.securityengineer.dto.CveRunResponse;
import com.nn2.docker_audit_api.securityengineer.dto.CveScheduleResponse;
import com.nn2.docker_audit_api.securityengineer.dto.CveSchedulesPageResponse;
import com.nn2.docker_audit_api.securityengineer.dto.CveScheduleUpsertRequest;
import com.nn2.docker_audit_api.securityengineer.dto.CveViolationSummaryResponse;
import com.nn2.docker_audit_api.securityengineer.service.CveAuditService;
import com.nn2.docker_audit_api.securityengineer.service.CveScannerService;
import com.nn2.docker_audit_api.securityengineer.service.CveScheduleService;

import jakarta.validation.Valid;

@Validated
@RestController
@RequestMapping({"/api/security", "/api/security-engineer"})
public class SecurityEngineerCveController {

    private final CveScannerService cveScannerService;
    private final CveScheduleService cveScheduleService;
    private final CveAuditService cveAuditService;

    public SecurityEngineerCveController(
            CveScannerService cveScannerService,
            CveScheduleService cveScheduleService,
            CveAuditService cveAuditService) {
        this.cveScannerService = cveScannerService;
        this.cveScheduleService = cveScheduleService;
        this.cveAuditService = cveAuditService;
    }

    @PostMapping("/cve/audits/run")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public CveRunResponse runCve(@RequestBody @Valid AuditRunRequest request, Authentication authentication) {
        JwtPrincipal principal = (JwtPrincipal) authentication.getPrincipal();
        CveScannerService.CveExecutionResult result = cveScannerService.runCveScan(request.hostId(), principal.id());
        String message = "COMPLETED".equals(result.scan().getStatus())
            ? "CVE-скан завершен. Метаданные сохранены в PostgreSQL, детали - в ClickHouse."
            : "CVE-скан завершился с ошибкой. Статус и метаданные сохранены в PostgreSQL. Причина: "
                + (result.errorMessage() == null ? "неизвестно" : result.errorMessage());
        return new CveRunResponse(
            result.scan().getId(),
            request.hostId(),
            result.scan().getStatus(),
            result.scan().getStartedAt() != null ? result.scan().getStartedAt().toString() : Instant.now().toString(),
            message);
    }

    @PostMapping("/cve/schedules")
    public CveScheduleResponse upsertCveSchedule(@RequestBody @Valid CveScheduleUpsertRequest request) {
        return cveScheduleService.upsertSchedule(request);
    }

    @GetMapping("/cve/schedules")
    public CveSchedulesPageResponse listCveSchedules(
            @RequestParam(name = "page", required = false) Integer page,
            @RequestParam(name = "size", required = false) Integer size,
            @RequestParam(name = "hostId", required = false) Long hostId,
            @RequestParam(name = "active", required = false) Boolean active) {
        return cveScheduleService.listSchedules(page, size, hostId, active);
    }

    @GetMapping("/cve/audits")
    public CveAuditStatusesPageResponse searchCveAudits(
            @RequestParam(name = "page", required = false) Integer page,
            @RequestParam(name = "size", required = false) Integer size,
            @RequestParam(name = "scanId", required = false) Long scanId,
            @RequestParam(name = "hostId", required = false) Long hostId,
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "from", required = false) String from,
            @RequestParam(name = "to", required = false) String to,
            @RequestParam(name = "sortBy", required = false) String sortBy,
            @RequestParam(name = "sortDir", required = false) String sortDir) {
        return cveAuditService.searchStatuses(page, size, scanId, hostId, status, from, to, sortBy, sortDir);
    }

    @GetMapping("/cve/audits/{id:\\d+}/summary")
    public CveViolationSummaryResponse cveSummary(@org.springframework.web.bind.annotation.PathVariable("id") Long id) {
        return cveAuditService.getSummary(id);
    }
}

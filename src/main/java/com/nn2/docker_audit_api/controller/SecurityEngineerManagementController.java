package com.nn2.docker_audit_api.controller;

import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.nn2.docker_audit_api.securityengineer.dto.AuditScheduleResponse;
import com.nn2.docker_audit_api.securityengineer.dto.AuditScheduleUpsertRequest;
import com.nn2.docker_audit_api.securityengineer.dto.CisRuleEnabledPatchRequest;
import com.nn2.docker_audit_api.securityengineer.dto.CisRuleItemResponse;
import com.nn2.docker_audit_api.securityengineer.dto.CisRulesPageResponse;
import com.nn2.docker_audit_api.securityengineer.dto.DockerHostsPageResponse;
import com.nn2.docker_audit_api.securityengineer.dto.NotificationSettingsResponse;
import com.nn2.docker_audit_api.securityengineer.dto.NotificationSettingsUpdateRequest;
import com.nn2.docker_audit_api.securityengineer.service.SecurityEngineerManagementService;

import jakarta.validation.Valid;

@Validated
@RestController
@RequestMapping({"/api/security", "/api/security-engineer"})
public class SecurityEngineerManagementController {

    private final SecurityEngineerManagementService managementService;

    public SecurityEngineerManagementController(SecurityEngineerManagementService managementService) {
        this.managementService = managementService;
    }

    @GetMapping("/rules")
    public CisRulesPageResponse listRules(
            @RequestParam(name = "page", required = false) Integer page,
            @RequestParam(name = "size", required = false) Integer size,
            @RequestParam(name = "severity", required = false) String severity,
            @RequestParam(name = "enabled", required = false) Boolean enabled) {
        return managementService.listRules(page, size, severity, enabled);
    }

    @PatchMapping("/rules/{id}/enabled")
    public CisRuleItemResponse patchRuleEnabled(
            @PathVariable("id") Long id,
            @RequestBody @Valid CisRuleEnabledPatchRequest request) {
        return managementService.updateRuleEnabled(id, request.enabled());
    }

    @GetMapping("/hosts")
    public DockerHostsPageResponse listHosts(
            @RequestParam(name = "page", required = false) Integer page,
            @RequestParam(name = "size", required = false) Integer size,
            @RequestParam(name = "active", required = false) Boolean active) {
        return managementService.listHosts(page, size, active);
    }

    @PostMapping("/schedules")
    public AuditScheduleResponse upsertSchedule(@RequestBody @Valid AuditScheduleUpsertRequest request) {
        return managementService.upsertSchedule(request);
    }

    @GetMapping("/notification-settings")
    public NotificationSettingsResponse getNotificationSettings() {
        return managementService.getNotificationSettings();
    }

    @PatchMapping("/notification-settings")
    public NotificationSettingsResponse updateNotificationSettings(
            @RequestBody @Valid NotificationSettingsUpdateRequest request) {
        return managementService.updateNotificationSettings(request.minSeverity());
    }
}

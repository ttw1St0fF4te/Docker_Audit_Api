package com.nn2.docker_audit_api.controller;

import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.nn2.docker_audit_api.developer.dto.dashboard.DeveloperDashboardContainerLoadResponse;
import com.nn2.docker_audit_api.developer.dto.dashboard.DeveloperDashboardHostContainerStateResponse;
import com.nn2.docker_audit_api.developer.dto.dashboard.DeveloperDashboardSeverityBreakdownResponse;
import com.nn2.docker_audit_api.developer.dto.dashboard.DeveloperDashboardTopRiskContainersResponse;
import com.nn2.docker_audit_api.developer.service.DeveloperDashboardService;

@Validated
@RestController
@RequestMapping("/api/developer/dashboard")
public class DeveloperDashboardController {

    private final DeveloperDashboardService developerDashboardService;

    public DeveloperDashboardController(DeveloperDashboardService developerDashboardService) {
        this.developerDashboardService = developerDashboardService;
    }

    @GetMapping("/container-state")
    public DeveloperDashboardHostContainerStateResponse containerState(
            @RequestParam(name = "hostId", required = false) Long hostId) {
        return developerDashboardService.getContainerStateByHosts(hostId);
    }

    @GetMapping("/container-load")
    public DeveloperDashboardContainerLoadResponse containerLoad(
            @RequestParam(name = "hostId", required = false) Long hostId,
            @RequestParam(name = "limit", required = false) Integer limit) {
        return developerDashboardService.getContainerLoad(hostId, limit);
    }

    @GetMapping("/top-risk-containers")
    public DeveloperDashboardTopRiskContainersResponse topRiskContainers(
            @RequestParam(name = "hostId", required = false) Long hostId,
            @RequestParam(name = "limit", required = false) Integer limit) {
        return developerDashboardService.getTopRiskContainers(hostId, limit);
    }

    @GetMapping("/severity-breakdown")
    public DeveloperDashboardSeverityBreakdownResponse severityBreakdown(
            @RequestParam(name = "hostId", required = false) Long hostId,
            @RequestParam(name = "period", required = false) String period) {
        return developerDashboardService.getSeverityBreakdown(hostId, period);
    }
}

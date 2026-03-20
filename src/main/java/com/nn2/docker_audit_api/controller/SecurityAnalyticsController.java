package com.nn2.docker_audit_api.controller;

import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.nn2.docker_audit_api.securityengineer.dto.analytics.AnalyticsOverviewResponse;
import com.nn2.docker_audit_api.securityengineer.dto.analytics.SecurityScoreTrendResponse;
import com.nn2.docker_audit_api.securityengineer.dto.analytics.SeverityTrendResponse;
import com.nn2.docker_audit_api.securityengineer.dto.analytics.TopHostRiskResponse;
import com.nn2.docker_audit_api.securityengineer.dto.analytics.TopRulesResponse;
import com.nn2.docker_audit_api.securityengineer.service.SecurityAnalyticsService;

@Validated
@RestController
@RequestMapping({"/api/security", "/api/security-engineer"})
public class SecurityAnalyticsController {

    private final SecurityAnalyticsService securityAnalyticsService;

    public SecurityAnalyticsController(SecurityAnalyticsService securityAnalyticsService) {
        this.securityAnalyticsService = securityAnalyticsService;
    }

    @GetMapping("/analytics/overview")
    public AnalyticsOverviewResponse overview(
            @RequestParam(name = "from", required = false) String from,
            @RequestParam(name = "to", required = false) String to,
            @RequestParam(name = "hostId", required = false) Long hostId) {
        return securityAnalyticsService.getOverview(from, to, hostId);
    }

    @GetMapping("/analytics/severity-trend")
    public SeverityTrendResponse severityTrend(
            @RequestParam(name = "from", required = false) String from,
            @RequestParam(name = "to", required = false) String to,
            @RequestParam(name = "bucket", required = false) String bucket,
            @RequestParam(name = "hostId", required = false) Long hostId) {
        return securityAnalyticsService.getSeverityTrend(from, to, bucket, hostId);
    }

    @GetMapping("/analytics/security-score-trend")
    public SecurityScoreTrendResponse securityScoreTrend(
            @RequestParam(name = "from", required = false) String from,
            @RequestParam(name = "to", required = false) String to,
            @RequestParam(name = "bucket", required = false) String bucket,
            @RequestParam(name = "hostId", required = false) Long hostId) {
        return securityAnalyticsService.getSecurityScoreTrend(from, to, bucket, hostId);
    }

    @GetMapping("/analytics/top-hosts")
    public TopHostRiskResponse topHosts(
            @RequestParam(name = "from", required = false) String from,
            @RequestParam(name = "to", required = false) String to,
            @RequestParam(name = "limit", required = false) Integer limit) {
        return securityAnalyticsService.getTopHosts(from, to, limit);
    }

    @GetMapping("/analytics/top-rules")
    public TopRulesResponse topRules(
            @RequestParam(name = "from", required = false) String from,
            @RequestParam(name = "to", required = false) String to,
            @RequestParam(name = "limit", required = false) Integer limit,
            @RequestParam(name = "hostId", required = false) Long hostId) {
        return securityAnalyticsService.getTopRules(from, to, limit, hostId);
    }
}

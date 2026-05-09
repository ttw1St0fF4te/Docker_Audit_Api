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
import com.nn2.docker_audit_api.securityengineer.service.CveAnalyticsService;

@Validated
@RestController
@RequestMapping({"/api/security/cve", "/api/security-engineer/cve"})
public class SecurityCveAnalyticsController {

    private final CveAnalyticsService cveAnalyticsService;

    public SecurityCveAnalyticsController(CveAnalyticsService cveAnalyticsService) {
        this.cveAnalyticsService = cveAnalyticsService;
    }

    @GetMapping("/analytics/overview")
    public AnalyticsOverviewResponse overview(
            @RequestParam(name = "from", required = false) String from,
            @RequestParam(name = "to", required = false) String to,
            @RequestParam(name = "hostId", required = false) Long hostId) {
        return cveAnalyticsService.getOverview(from, to, hostId);
    }

    @GetMapping("/analytics/severity-trend")
    public SeverityTrendResponse severityTrend(
            @RequestParam(name = "from", required = false) String from,
            @RequestParam(name = "to", required = false) String to,
            @RequestParam(name = "bucket", required = false) String bucket,
            @RequestParam(name = "hostId", required = false) Long hostId) {
        return cveAnalyticsService.getSeverityTrend(from, to, bucket, hostId);
    }

    @GetMapping("/analytics/security-score-trend")
    public SecurityScoreTrendResponse securityScoreTrend(
            @RequestParam(name = "from", required = false) String from,
            @RequestParam(name = "to", required = false) String to,
            @RequestParam(name = "bucket", required = false) String bucket,
            @RequestParam(name = "hostId", required = false) Long hostId) {
        return cveAnalyticsService.getSecurityScoreTrend(from, to, bucket, hostId);
    }

    @GetMapping("/analytics/top-hosts")
    public TopHostRiskResponse topHosts(
            @RequestParam(name = "from", required = false) String from,
            @RequestParam(name = "to", required = false) String to,
            @RequestParam(name = "limit", required = false) Integer limit) {
        return cveAnalyticsService.getTopHosts(from, to, limit);
    }

    @GetMapping("/analytics/top-rules")
    public TopRulesResponse topRules(
            @RequestParam(name = "from", required = false) String from,
            @RequestParam(name = "to", required = false) String to,
            @RequestParam(name = "limit", required = false) Integer limit,
            @RequestParam(name = "hostId", required = false) Long hostId) {
        return cveAnalyticsService.getTopRules(from, to, limit, hostId);
    }
}

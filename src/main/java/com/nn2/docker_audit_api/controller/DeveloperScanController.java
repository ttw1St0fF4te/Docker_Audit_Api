package com.nn2.docker_audit_api.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.nn2.docker_audit_api.auth.jwt.JwtPrincipal;
import com.nn2.docker_audit_api.developer.dto.DeveloperScanViolationsResponse;
import com.nn2.docker_audit_api.developer.service.DeveloperScanViolationsService;

@Validated
@RestController
@RequestMapping("/api/developer/scans")
public class DeveloperScanController {

    private static final Logger log = LoggerFactory.getLogger(DeveloperScanController.class);

    private final DeveloperScanViolationsService developerScanViolationsService;

    public DeveloperScanController(DeveloperScanViolationsService developerScanViolationsService) {
        this.developerScanViolationsService = developerScanViolationsService;
    }

    @GetMapping("/{scanId}/violations")
    public DeveloperScanViolationsResponse getViolations(
            Authentication authentication,
            @PathVariable("scanId") Long scanId,
            @RequestParam(name = "scanType", required = false, defaultValue = "CIS") String scanType) {
        JwtPrincipal principal = (JwtPrincipal) authentication.getPrincipal();
        log.info("getViolations called: developerUserId={}, scanId={}, scanType={}", principal.id(), scanId, scanType);
        return developerScanViolationsService.getViolations(principal.id(), scanId, scanType);
    }
}

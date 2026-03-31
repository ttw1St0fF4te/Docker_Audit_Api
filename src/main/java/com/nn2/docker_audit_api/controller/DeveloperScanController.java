package com.nn2.docker_audit_api.controller;

import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nn2.docker_audit_api.auth.jwt.JwtPrincipal;
import com.nn2.docker_audit_api.developer.dto.DeveloperScanViolationsResponse;
import com.nn2.docker_audit_api.developer.service.DeveloperScanViolationsService;

@Validated
@RestController
@RequestMapping("/api/developer/scans")
public class DeveloperScanController {

    private final DeveloperScanViolationsService developerScanViolationsService;

    public DeveloperScanController(DeveloperScanViolationsService developerScanViolationsService) {
        this.developerScanViolationsService = developerScanViolationsService;
    }

    @GetMapping("/{scanId}/violations")
    public DeveloperScanViolationsResponse getViolations(
            Authentication authentication,
            @PathVariable("scanId") Long scanId) {
        JwtPrincipal principal = (JwtPrincipal) authentication.getPrincipal();
        return developerScanViolationsService.getViolations(principal.id(), scanId);
    }
}

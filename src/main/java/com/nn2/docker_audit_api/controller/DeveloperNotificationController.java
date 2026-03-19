package com.nn2.docker_audit_api.controller;

import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.nn2.docker_audit_api.auth.jwt.JwtPrincipal;
import com.nn2.docker_audit_api.developer.dto.DeveloperNotificationItemResponse;
import com.nn2.docker_audit_api.developer.dto.DeveloperNotificationsResponse;
import com.nn2.docker_audit_api.developer.service.DeveloperNotificationService;

import org.springframework.security.core.Authentication;

@Validated
@RestController
@RequestMapping("/api/developer/notifications")
public class DeveloperNotificationController {

    private final DeveloperNotificationService developerNotificationService;

    public DeveloperNotificationController(DeveloperNotificationService developerNotificationService) {
        this.developerNotificationService = developerNotificationService;
    }

    @GetMapping
    public DeveloperNotificationsResponse listNotifications(
            Authentication authentication,
            @RequestParam(name = "page", required = false) Integer page,
            @RequestParam(name = "size", required = false) Integer size,
            @RequestParam(name = "read", required = false) Boolean read,
            @RequestParam(name = "severity", required = false) String severity) {
        JwtPrincipal principal = (JwtPrincipal) authentication.getPrincipal();
        return developerNotificationService.listNotifications(principal.id(), page, size, read, severity);
    }

    @PatchMapping("/{id}/read")
    public DeveloperNotificationItemResponse markRead(
            Authentication authentication,
            @PathVariable("id") Long id) {
        JwtPrincipal principal = (JwtPrincipal) authentication.getPrincipal();
        return developerNotificationService.markAsRead(principal.id(), id);
    }
}

package com.nn2.docker_audit_api.developer.dto;

public record DeveloperNotificationItemResponse(
        Long id,
        Long scanId,
        String severity,
        String title,
        String summary,
        String message,
        boolean isRead,
        boolean read,
        String createdAt,
        String readAt) {
}

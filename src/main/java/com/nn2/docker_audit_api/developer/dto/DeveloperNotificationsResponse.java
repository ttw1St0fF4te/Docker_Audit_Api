package com.nn2.docker_audit_api.developer.dto;

import java.util.List;

public record DeveloperNotificationsResponse(
        List<DeveloperNotificationItemResponse> items,
        long total,
        int page,
        int size) {
}

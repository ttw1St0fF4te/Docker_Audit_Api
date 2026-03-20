package com.nn2.docker_audit_api.securityengineer.dto;

import jakarta.validation.constraints.NotBlank;

public record NotificationSettingsUpdateRequest(
        @NotBlank(message = "minSeverity обязателен")
        String minSeverity) {
}

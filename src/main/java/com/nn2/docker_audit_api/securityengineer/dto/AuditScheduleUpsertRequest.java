package com.nn2.docker_audit_api.securityengineer.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

public record AuditScheduleUpsertRequest(
        @NotNull(message = "Host ID обязателен")
        @Positive(message = "Host ID должен быть положительным")
        Long hostId,

        @NotBlank(message = "cron_expression обязателен")
        String cronExpression,

        Boolean active) {
}

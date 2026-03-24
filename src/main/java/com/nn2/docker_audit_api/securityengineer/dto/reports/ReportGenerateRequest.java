package com.nn2.docker_audit_api.securityengineer.dto.reports;

import jakarta.validation.constraints.NotBlank;

public record ReportGenerateRequest(
        @NotBlank(message = "scope обязателен")
        String scope,
        @NotBlank(message = "format обязателен")
        String format,
        String from,
        String to,
        String bucket,
        Long hostId) {
}

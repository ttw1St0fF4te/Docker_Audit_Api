package com.nn2.docker_audit_api.securityengineer.dto.reports;

public record ReportGenerateResponse(
        String scope,
        String format,
        String fileName,
        String savedPath,
        String generatedAt,
        String message) {
}

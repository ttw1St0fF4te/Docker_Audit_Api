package com.nn2.docker_audit_api.securityengineer.dto;

public record DockerHostItemResponse(
        Long id,
        String name,
        String baseUrl,
        String hostType,
        boolean tlsEnabled,
        String authType,
        String certPath,
        boolean active,
        boolean deleted,
        String createdAt) {
}

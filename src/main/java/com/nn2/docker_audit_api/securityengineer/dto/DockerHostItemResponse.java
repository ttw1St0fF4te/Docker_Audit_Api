package com.nn2.docker_audit_api.securityengineer.dto;

public record DockerHostItemResponse(
        Long id,
        String name,
        String hostUrl,
        String authType,
        String certPath,
        boolean active,
        String createdAt) {
}

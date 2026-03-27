package com.nn2.docker_audit_api.admin.dto;

public record AdminDockerHostDeleteResponse(
        Long id,
        String name,
        boolean hardDeleted,
        String message) {
}

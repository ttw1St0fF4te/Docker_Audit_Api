package com.nn2.docker_audit_api.admin.dto;

public record AdminDockerHostConnectionTestResponse(
        boolean connected,
        String message,
        int containersFound) {
}

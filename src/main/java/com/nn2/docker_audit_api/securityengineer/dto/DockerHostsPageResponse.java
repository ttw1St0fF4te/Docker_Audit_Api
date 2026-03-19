package com.nn2.docker_audit_api.securityengineer.dto;

import java.util.List;

public record DockerHostsPageResponse(
        List<DockerHostItemResponse> items,
        long total,
        int page,
        int size) {
}

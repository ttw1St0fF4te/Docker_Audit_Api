package com.nn2.docker_audit_api.admin.dto;

import com.nn2.docker_audit_api.securityengineer.model.DockerHostType;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record AdminDockerHostConnectionTestRequest(
        @NotBlank(message = "Укажите endpoint Docker")
        @Size(max = 255, message = "Endpoint Docker не должен превышать 255 символов")
        String baseUrl,
        @NotNull(message = "Укажите тип хоста")
        DockerHostType hostType) {
}

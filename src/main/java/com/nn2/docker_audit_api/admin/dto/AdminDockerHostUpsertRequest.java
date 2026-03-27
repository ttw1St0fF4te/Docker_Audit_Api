package com.nn2.docker_audit_api.admin.dto;

import com.nn2.docker_audit_api.securityengineer.model.DockerHostType;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record AdminDockerHostUpsertRequest(
        @NotBlank(message = "Укажите имя хоста")
        @Size(max = 100, message = "Имя хоста не должно превышать 100 символов")
        String name,
        @NotBlank(message = "Укажите endpoint Docker")
        @Size(max = 255, message = "Endpoint Docker не должен превышать 255 символов")
        String baseUrl,
        @NotNull(message = "Укажите тип хоста")
        DockerHostType hostType,
        Boolean tlsEnabled,
        @Size(max = 20, message = "authType не должен превышать 20 символов")
        String authType,
        @Size(max = 255, message = "certPath не должен превышать 255 символов")
        String certPath,
        Boolean active) {
}

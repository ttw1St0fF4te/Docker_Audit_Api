package com.nn2.docker_audit_api.securityengineer.dto;

import jakarta.validation.constraints.NotNull;

public record CisRuleEnabledPatchRequest(
        @NotNull(message = "Поле enabled обязательно")
        Boolean enabled) {
}

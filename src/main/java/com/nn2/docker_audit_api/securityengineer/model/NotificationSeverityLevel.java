package com.nn2.docker_audit_api.securityengineer.model;

import java.util.Locale;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public enum NotificationSeverityLevel {
    LOW(0),
    MEDIUM(1),
    HIGH(2),
    CRITICAL(3);

    private final int rank;

    NotificationSeverityLevel(int rank) {
        this.rank = rank;
    }

    public boolean includes(String severity) {
        return rankOf(severity) >= this.rank;
    }

    public static NotificationSeverityLevel fromSetting(String rawValue) {
        if (rawValue == null || rawValue.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "minSeverity обязателен");
        }

        String normalized = rawValue.trim().toUpperCase(Locale.ROOT);
        try {
            return NotificationSeverityLevel.valueOf(normalized);
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "minSeverity должен быть одним из: LOW, MEDIUM, HIGH, CRITICAL");
        }
    }

    public static int rankOf(String severity) {
        if (severity == null) {
            return -1;
        }
        return switch (severity.trim().toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> 3;
            case "HIGH" -> 2;
            case "MEDIUM" -> 1;
            case "LOW" -> 0;
            default -> -1;
        };
    }
}

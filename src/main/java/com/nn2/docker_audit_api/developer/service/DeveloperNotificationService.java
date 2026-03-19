package com.nn2.docker_audit_api.developer.service;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import com.nn2.docker_audit_api.developer.dto.DeveloperNotificationItemResponse;
import com.nn2.docker_audit_api.developer.dto.DeveloperNotificationsResponse;
import com.nn2.docker_audit_api.developer.entity.DeveloperNotificationEntity;
import com.nn2.docker_audit_api.developer.repository.DeveloperNotificationRepository;

@Service
public class DeveloperNotificationService {

    private static final int DEFAULT_PAGE = 0;
    private static final int DEFAULT_SIZE = 20;
    private static final int MAX_SIZE = 200;

    private final DeveloperNotificationRepository developerNotificationRepository;

    public DeveloperNotificationService(DeveloperNotificationRepository developerNotificationRepository) {
        this.developerNotificationRepository = developerNotificationRepository;
    }

    public DeveloperNotificationsResponse listNotifications(
            Long developerUserId,
            Integer page,
            Integer size,
            Boolean read,
            String severity) {
        int safePage = normalizePage(page);
        int safeSize = normalizeSize(size);

        List<DeveloperNotificationEntity> all = developerNotificationRepository
            .findByDeveloperUserIdOrderByCreatedAtDesc(developerUserId);

        Stream<DeveloperNotificationEntity> stream = all.stream();

        if (read != null) {
            stream = stream.filter(item -> item.isRead() == read);
        }

        if (severity != null && !severity.isBlank()) {
            String normalized = severity.trim().toUpperCase(Locale.ROOT);
            stream = stream.filter(item -> normalized.equalsIgnoreCase(item.getSeverity()));
        }

        List<DeveloperNotificationEntity> filtered = stream.toList();
        List<DeveloperNotificationItemResponse> items = paginate(filtered, safePage, safeSize).stream()
            .map(this::toItem)
            .toList();

        return new DeveloperNotificationsResponse(items, filtered.size(), safePage, safeSize);
    }

    @Transactional
    public DeveloperNotificationItemResponse markAsRead(Long developerUserId, Long notificationId) {
        DeveloperNotificationEntity notification = developerNotificationRepository
            .findByIdAndDeveloperUserId(notificationId, developerUserId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Уведомление не найдено"));

        if (!notification.isRead()) {
            notification.setRead(true);
            notification.setReadAt(Instant.now());
            developerNotificationRepository.save(notification);
        }

        return toItem(notification);
    }

    private DeveloperNotificationItemResponse toItem(DeveloperNotificationEntity entity) {
        return new DeveloperNotificationItemResponse(
            entity.getId(),
            entity.getScanId(),
            entity.getSeverity(),
            entity.getTitle(),
            entity.getMessage(),
            entity.isRead(),
            toIso(entity.getCreatedAt()),
            toIso(entity.getReadAt()));
    }

    private <T> List<T> paginate(List<T> items, int page, int size) {
        int from = page * size;
        if (from >= items.size()) {
            return List.of();
        }
        int to = Math.min(from + size, items.size());
        return items.subList(from, to);
    }

    private int normalizePage(Integer page) {
        if (page == null || page < 0) {
            return DEFAULT_PAGE;
        }
        return page;
    }

    private int normalizeSize(Integer size) {
        if (size == null) {
            return DEFAULT_SIZE;
        }
        if (size < 1) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "size должен быть >= 1");
        }
        if (size > MAX_SIZE) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "size не должен быть больше " + MAX_SIZE);
        }
        return size;
    }

    private String toIso(Instant instant) {
        return instant == null ? null : instant.toString();
    }
}

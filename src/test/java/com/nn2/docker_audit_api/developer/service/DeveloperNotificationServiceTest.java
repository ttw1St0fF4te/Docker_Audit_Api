package com.nn2.docker_audit_api.developer.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

import com.nn2.docker_audit_api.developer.dto.DeveloperNotificationItemResponse;
import com.nn2.docker_audit_api.developer.dto.DeveloperNotificationsReadAllResponse;
import com.nn2.docker_audit_api.developer.dto.DeveloperNotificationsResponse;
import com.nn2.docker_audit_api.developer.entity.DeveloperNotificationEntity;
import com.nn2.docker_audit_api.developer.repository.DeveloperNotificationRepository;

@ExtendWith(MockitoExtension.class)
class DeveloperNotificationServiceTest {

    @Mock
    private DeveloperNotificationRepository developerNotificationRepository;

    @InjectMocks
    private DeveloperNotificationService service;

    private DeveloperNotificationEntity unread;
    private DeveloperNotificationEntity read;

    @BeforeEach
    void setUp() {
        unread = buildEntity(1L, false);
        read = buildEntity(2L, true);
    }

    @Test
    void listNotificationsFiltersByStatusUnread() {
        when(developerNotificationRepository.findByDeveloperUserIdOrderByCreatedAtDesc(10L))
            .thenReturn(List.of(unread, read));

        DeveloperNotificationsResponse response = service.listNotifications(10L, 0, 20, "UNREAD", null, null);

        assertEquals(1, response.items().size());
        assertEquals(1L, response.items().get(0).id());
        assertEquals(false, response.items().get(0).isRead());
    }

    @Test
    void listNotificationsRejectsInvalidStatus() {
        assertThrows(ResponseStatusException.class,
            () -> service.listNotifications(10L, 0, 20, "BAD", null, null));
    }

    @Test
    void getNotificationReturnsOnlyOwnNotification() {
        when(developerNotificationRepository.findByIdAndDeveloperUserId(1L, 10L))
            .thenReturn(Optional.of(unread));

        DeveloperNotificationItemResponse item = service.getNotification(10L, 1L);

        assertEquals(1L, item.id());
        assertEquals("Скан завершен", item.summary());
        assertEquals(false, item.isRead());
    }

    @Test
    void markAllReadUpdatesOnlyUnread() {
        when(developerNotificationRepository.findByDeveloperUserIdAndReadFalseOrderByCreatedAtDesc(10L))
            .thenReturn(List.of(unread));

        DeveloperNotificationsReadAllResponse response = service.markAllRead(10L);

        assertEquals(1, response.updatedCount());
        assertEquals(true, unread.isRead());
        assertNotNull(unread.getReadAt());
        verify(developerNotificationRepository, times(1)).saveAll(any());
    }

    @Test
    void markAllReadReturnsZeroWhenNoUnread() {
        when(developerNotificationRepository.findByDeveloperUserIdAndReadFalseOrderByCreatedAtDesc(10L))
            .thenReturn(List.of());

        DeveloperNotificationsReadAllResponse response = service.markAllRead(10L);

        assertEquals(0, response.updatedCount());
        verify(developerNotificationRepository, never()).saveAll(any());
    }

    private DeveloperNotificationEntity buildEntity(Long id, boolean isRead) {
        DeveloperNotificationEntity entity = new DeveloperNotificationEntity();
        entity.setId(id);
        entity.setDeveloperUserId(10L);
        entity.setScanId(100L + id);
        entity.setSeverity("HIGH");
        entity.setTitle("Найдены HIGH нарушения");
        entity.setMessage("Скан завершен");
        entity.setRead(isRead);
        entity.setCreatedAt(Instant.parse("2026-03-29T10:00:00Z"));
        entity.setReadAt(isRead ? Instant.parse("2026-03-29T11:00:00Z") : null);
        return entity;
    }
}

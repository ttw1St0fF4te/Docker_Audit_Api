package com.nn2.docker_audit_api.developer.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.server.ResponseStatusException;

import com.nn2.docker_audit_api.developer.dto.DeveloperScanViolationsResponse;
import com.nn2.docker_audit_api.developer.dto.DeveloperViolationItemResponse;
import com.nn2.docker_audit_api.developer.repository.DeveloperNotificationRepository;
import com.nn2.docker_audit_api.securityengineer.entity.ScanEntity;
import com.nn2.docker_audit_api.securityengineer.repository.ScanRepository;

@ExtendWith(MockitoExtension.class)
class DeveloperScanViolationsServiceTest {

    @Mock
    private DeveloperNotificationRepository developerNotificationRepository;

    @Mock
    private ScanRepository scanRepository;

    @Mock
    private JdbcTemplate clickHouseJdbcTemplate;

    @InjectMocks
    private DeveloperScanViolationsService service;

    private ScanEntity scan;

    @BeforeEach
    void setUp() {
        scan = new ScanEntity();
        scan.setId(17L);
        scan.setHostId(1L);
        scan.setStatus("COMPLETED");
        scan.setStartedAt(Instant.parse("2026-03-29T09:00:00Z"));
        scan.setFinishedAt(Instant.parse("2026-03-29T09:01:00Z"));
        scan.setTotalContainers(3);
        scan.setTotalViolations(2);
        scan.setCriticalCount(1);
        scan.setHighCount(1);
        scan.setMediumCount(0);
        scan.setLowCount(0);
    }

    @Test
    void getViolationsReturnsDetailsWhenClickhouseHasRows() {
        when(developerNotificationRepository.existsByDeveloperUserIdAndScanId(10L, 17L)).thenReturn(true);
        when(scanRepository.findById(17L)).thenReturn(Optional.of(scan));
        when(clickHouseJdbcTemplate.query(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any(org.springframework.jdbc.core.RowMapper.class)))
            .thenReturn(List.of(
                new DeveloperViolationItemResponse(1L, "host-1", "container-a", "5.1", "No privileged", "CRITICAL", "fix A", Timestamp.from(Instant.parse("2026-03-29T09:00:20Z")).toInstant().toString()),
                new DeveloperViolationItemResponse(1L, "host-1", "container-b", "5.2", "No host pid", "HIGH", "fix B", Timestamp.from(Instant.parse("2026-03-29T09:00:30Z")).toInstant().toString())
            ));

        DeveloperScanViolationsResponse response = service.getViolations(10L, 17L);

        assertTrue(response.detailsAvailable());
        assertEquals(2, response.violations().size());
        assertEquals(2, response.summary().totalViolations());
        assertEquals(2, response.summary().affectedContainers());
        assertEquals(1, response.summary().criticalCount());
        assertEquals(1, response.summary().highCount());
    }

    @Test
    void getViolationsReturnsFallbackWhenClickhouseRowsMissing() {
        when(developerNotificationRepository.existsByDeveloperUserIdAndScanId(10L, 17L)).thenReturn(true);
        when(scanRepository.findById(17L)).thenReturn(Optional.of(scan));
        when(clickHouseJdbcTemplate.query(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any(org.springframework.jdbc.core.RowMapper.class)))
            .thenReturn(List.of());

        DeveloperScanViolationsResponse response = service.getViolations(10L, 17L);

        assertFalse(response.detailsAvailable());
        assertEquals(0, response.violations().size());
        assertEquals(2, response.summary().totalViolations());
        assertEquals(3, response.summary().affectedContainers());
    }

    @Test
    void getViolationsRejectsForeignScan() {
        when(developerNotificationRepository.existsByDeveloperUserIdAndScanId(10L, 17L)).thenReturn(false);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> service.getViolations(10L, 17L));

        assertEquals(HttpStatus.NOT_FOUND, ex.getStatusCode());
    }
}

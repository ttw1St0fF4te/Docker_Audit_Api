package com.nn2.docker_audit_api.developer.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.MailSendException;

import com.nn2.docker_audit_api.auth.entity.AppUser;
import com.nn2.docker_audit_api.auth.model.RoleCode;
import com.nn2.docker_audit_api.auth.repository.AppUserRepository;
import com.nn2.docker_audit_api.developer.repository.DeveloperNotificationRepository;
import com.nn2.docker_audit_api.mail.service.EmailSenderService;
import com.nn2.docker_audit_api.mail.service.EmailTemplateService;
import com.nn2.docker_audit_api.securityengineer.entity.ScanEntity;
import com.nn2.docker_audit_api.securityengineer.model.NotificationSeverityLevel;
import com.nn2.docker_audit_api.securityengineer.service.NotificationSettingsService;

@ExtendWith(MockitoExtension.class)
class InAppNotificationDispatcherTest {

    @Mock
    private AppUserRepository appUserRepository;

    @Mock
    private DeveloperNotificationRepository developerNotificationRepository;

    @Mock
    private NotificationSettingsService notificationSettingsService;

    @Mock
    private EmailSenderService emailSenderService;

    @Mock
    private EmailTemplateService emailTemplateService;

    @InjectMocks
    private InAppNotificationDispatcher dispatcher;

    private ScanEntity scan;
    private AppUser developerA;
    private AppUser developerB;

    @BeforeEach
    void setUp() {
        scan = new ScanEntity();
        scan.setId(100L);
        scan.setHostId(1L);
        scan.setCriticalCount(1);
        scan.setHighCount(0);
        scan.setMediumCount(0);
        scan.setLowCount(0);
        scan.setTotalViolations(1);
        scan.setTotalContainers(3);

        developerA = new AppUser();
        developerA.setId(10L);
        developerA.setEmail("dev1@example.com");

        developerB = new AppUser();
        developerB.setId(11L);
        developerB.setEmail("dev2@example.com");
    }

    @Test
    void dispatchForCompletedScanSavesNotificationsAndEmailsAllDevelopers() {
        when(notificationSettingsService.getThreshold()).thenReturn(NotificationSeverityLevel.LOW);
        when(appUserRepository.findByRoleCodeAndEnabledTrueAndDeletedFalse(RoleCode.DEVELOPER))
            .thenReturn(List.of(developerA, developerB));
        when(emailTemplateService.developerVulnerabilitySubject(anyLong(), eq("CRITICAL")))
            .thenReturn("subject");
        when(emailTemplateService.developerVulnerabilityBody(anyLong(), anyLong(), eq(1), eq(0), eq(0), eq(0), eq(1), eq(3)))
            .thenReturn("body");
        when(emailSenderService.sendPlainText(eq("dev1@example.com"), eq("subject"), eq("body"))).thenReturn(true);
        when(emailSenderService.sendPlainText(eq("dev2@example.com"), eq("subject"), eq("body"))).thenReturn(true);

        dispatcher.dispatchForCompletedScan(scan);

        verify(developerNotificationRepository, times(1)).saveAll(any());
        verify(emailSenderService, times(1)).sendPlainText("dev1@example.com", "subject", "body");
        verify(emailSenderService, times(1)).sendPlainText("dev2@example.com", "subject", "body");
    }

    @Test
    void dispatchForCompletedScanContinuesWhenOneEmailFails() {
        when(notificationSettingsService.getThreshold()).thenReturn(NotificationSeverityLevel.LOW);
        when(appUserRepository.findByRoleCodeAndEnabledTrueAndDeletedFalse(RoleCode.DEVELOPER))
            .thenReturn(List.of(developerA, developerB));
        when(emailTemplateService.developerVulnerabilitySubject(anyLong(), eq("CRITICAL")))
            .thenReturn("subject");
        when(emailTemplateService.developerVulnerabilityBody(anyLong(), anyLong(), eq(1), eq(0), eq(0), eq(0), eq(1), eq(3)))
            .thenReturn("body");
        when(emailSenderService.sendPlainText(eq("dev1@example.com"), eq("subject"), eq("body")))
            .thenThrow(new MailSendException("smtp down"));
        when(emailSenderService.sendPlainText(eq("dev2@example.com"), eq("subject"), eq("body"))).thenReturn(true);

        dispatcher.dispatchForCompletedScan(scan);

        verify(developerNotificationRepository, times(1)).saveAll(any());
        verify(emailSenderService, times(1)).sendPlainText("dev1@example.com", "subject", "body");
        verify(emailSenderService, times(1)).sendPlainText("dev2@example.com", "subject", "body");
    }
}

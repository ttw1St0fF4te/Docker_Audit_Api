package com.nn2.docker_audit_api.controller;

import java.time.Instant;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.nn2.docker_audit_api.securityengineer.config.DockerAuditProperties;
import com.nn2.docker_audit_api.securityengineer.docker.DockerClientService;
import com.nn2.docker_audit_api.securityengineer.docker.DockerConnectionException;
import com.nn2.docker_audit_api.securityengineer.docker.model.ContainerSnapshot;
import com.nn2.docker_audit_api.securityengineer.dto.AuditRunRequest;
import com.nn2.docker_audit_api.securityengineer.dto.AuditRunResponse;
import com.nn2.docker_audit_api.securityengineer.dto.AuditStatusResponse;
import com.nn2.docker_audit_api.securityengineer.dto.AuditViolationSummaryResponse;
import com.nn2.docker_audit_api.securityengineer.dto.ContainerCisAuditResponse;
import com.nn2.docker_audit_api.securityengineer.dto.RecentAuditsResponse;
import com.nn2.docker_audit_api.securityengineer.entity.ScanEntity;
import com.nn2.docker_audit_api.securityengineer.service.AuditService;
import com.nn2.docker_audit_api.securityengineer.service.CisRuleEngine;
import com.nn2.docker_audit_api.auth.jwt.JwtPrincipal;

import jakarta.validation.Valid;

@Validated
@RestController
@RequestMapping({"/api/security", "/api/security-engineer"})
public class SecurityEngineerController {

	private final DockerAuditProperties dockerAuditProperties;
	private final DockerClientService dockerClientService;
	private final CisRuleEngine cisRuleEngine;
	private final AuditService auditService;

	public SecurityEngineerController(
			DockerAuditProperties dockerAuditProperties,
			DockerClientService dockerClientService,
			CisRuleEngine cisRuleEngine,
			AuditService auditService) {
		this.dockerAuditProperties = dockerAuditProperties;
		this.dockerClientService = dockerClientService;
		this.cisRuleEngine = cisRuleEngine;
		this.auditService = auditService;
	}

	@PostMapping("/audits/run")
	@ResponseStatus(HttpStatus.ACCEPTED)
	public AuditRunResponse runAudit(@RequestBody @Valid AuditRunRequest request, Authentication authentication) {
		JwtPrincipal principal = (JwtPrincipal) authentication.getPrincipal();
		AuditService.AuditExecutionResult executionResult = auditService.runAudit(request.hostId(), principal.id());
		ScanEntity completedScan = executionResult.scan();
		String message = "COMPLETED".equals(completedScan.getStatus())
			? "Скан завершен. Метаданные сохранены в PostgreSQL, детали - в ClickHouse."
			: "Скан завершился с ошибкой. Статус и метаданные сохранены в PostgreSQL. Причина: "
				+ (executionResult.errorMessage() == null ? "неизвестно" : executionResult.errorMessage());
		return new AuditRunResponse(
			completedScan.getId(),
			request.hostId(),
			completedScan.getStatus(),
			completedScan.getStartedAt() != null ? completedScan.getStartedAt().toString() : Instant.now().toString(),
			message);
	}

	@GetMapping("/audits/{id:\\d+}")
	public AuditStatusResponse getAuditStatus(@PathVariable("id") Long id) {
		return auditService.getStatus(id);
	}

	@GetMapping("/audits/recent")
	public RecentAuditsResponse recentAudits() {
		List<AuditStatusResponse> items = auditService.getRecentStatuses();
		return new RecentAuditsResponse(items, (long) items.size());
	}

	@GetMapping("/audits/{id:\\d+}/summary")
	public AuditViolationSummaryResponse auditSummary(@PathVariable("id") Long id) {
		return auditService.getSummary(id);
	}

	@GetMapping("/config/docker-host")
	public String dockerHostConfig() {
		return dockerAuditProperties.getDefaultHostUrl();
	}

	@GetMapping("/docker/containers")
	public List<ContainerSnapshot> dockerContainers(@RequestParam(name = "hostUrl", required = false) String hostUrl) {
		try {
			return dockerClientService.listContainerSnapshots(hostUrl);
		} catch (DockerConnectionException ex) {
			throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, ex.getMessage());
		}
	}

	@GetMapping("/docker/audit-preview")
	public List<ContainerCisAuditResponse> dockerAuditPreview(@RequestParam(name = "hostUrl", required = false) String hostUrl) {
		try {
			return cisRuleEngine.evaluateActiveRules(hostUrl);
		} catch (DockerConnectionException ex) {
			throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, ex.getMessage());
		} catch (IllegalStateException ex) {
			throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
	}
}

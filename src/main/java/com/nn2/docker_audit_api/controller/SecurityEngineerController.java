package com.nn2.docker_audit_api.controller;

import java.time.Instant;
import java.util.List;

import org.springframework.http.HttpStatus;
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
import com.nn2.docker_audit_api.securityengineer.dto.RecentAuditsResponse;

import jakarta.validation.Valid;

@Validated
@RestController
@RequestMapping("/api/security")
public class SecurityEngineerController {

	private final DockerAuditProperties dockerAuditProperties;
	private final DockerClientService dockerClientService;

	public SecurityEngineerController(DockerAuditProperties dockerAuditProperties, DockerClientService dockerClientService) {
		this.dockerAuditProperties = dockerAuditProperties;
		this.dockerClientService = dockerClientService;
	}

	@PostMapping("/audits/run")
	@ResponseStatus(HttpStatus.ACCEPTED)
	public AuditRunResponse runAudit(@RequestBody @Valid AuditRunRequest request) {
		return new AuditRunResponse(
			0L,
			request.hostId(),
			"QUEUED",
			Instant.now().toString(),
			"Контракт endpoint готов. Реализация запуска аудита будет добавлена на следующих этапах.");
	}

	@GetMapping("/audits/{id}")
	public AuditStatusResponse getAuditStatus(@PathVariable Long id) {
		return new AuditStatusResponse(
			id,
			1L,
			"NOT_IMPLEMENTED",
			null,
			null,
			0,
			0,
			0,
			0,
			0,
			0);
	}

	@GetMapping("/audits/recent")
	public RecentAuditsResponse recentAudits() {
		AuditStatusResponse sample = new AuditStatusResponse(
			1L,
			1L,
			"COMPLETED",
			"2026-03-16T10:00:00Z",
			"2026-03-16T10:02:30Z",
			8,
			3,
			1,
			1,
			1,
			0);
		return new RecentAuditsResponse(List.of(sample), 1L);
	}

	@GetMapping("/audits/{id}/summary")
	public AuditViolationSummaryResponse auditSummary(@PathVariable Long id) {
		return new AuditViolationSummaryResponse(
			id,
			100,
			3,
			1,
			1,
			1,
			0);
	}

	@GetMapping("/config/docker-host")
	public String dockerHostConfig() {
		return dockerAuditProperties.getDefaultHostUrl();
	}

	@GetMapping("/docker/containers")
	public List<ContainerSnapshot> dockerContainers(@RequestParam(required = false) String hostUrl) {
		try {
			return dockerClientService.listContainerSnapshots(hostUrl);
		} catch (DockerConnectionException ex) {
			throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, ex.getMessage());
		}
	}
}

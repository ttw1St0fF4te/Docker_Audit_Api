package com.nn2.docker_audit_api.controller;

import com.nn2.docker_audit_api.service.InfrastructureHealthService;
import com.nn2.docker_audit_api.service.InfrastructureHealthService.HealthResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class HealthController {

	private final InfrastructureHealthService infrastructureHealthService;

	public HealthController(InfrastructureHealthService infrastructureHealthService) {
		this.infrastructureHealthService = infrastructureHealthService;
	}

	@GetMapping("/health")
	public ResponseEntity<HealthResponse> getHealth() {
		HealthResponse response = infrastructureHealthService.check();
		HttpStatus status = response.status().equals("UP") ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE;
		return ResponseEntity.status(status).body(response);
	}
}
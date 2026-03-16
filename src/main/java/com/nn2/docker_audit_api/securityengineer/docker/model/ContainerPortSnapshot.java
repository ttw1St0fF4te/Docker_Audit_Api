package com.nn2.docker_audit_api.securityengineer.docker.model;

public record ContainerPortSnapshot(
		String ip,
		Integer privatePort,
		Integer publicPort,
		String type) {
}

package com.nn2.docker_audit_api.securityengineer.docker.model;

import java.util.List;

public record ContainerSnapshot(
		String containerId,
		String containerName,
		String image,
		String state,
		String status,
		String createdAt,
		String hostUrl,
		boolean privileged,
		boolean readOnlyRootFs,
		String networkMode,
		String pidMode,
		String ipcMode,
		String utsMode,
		String user,
		String healthStatus,
		Long memoryLimit,
		Long nanoCpuLimit,
		boolean dockerSocketMounted,
		List<ContainerPortSnapshot> ports) {
}

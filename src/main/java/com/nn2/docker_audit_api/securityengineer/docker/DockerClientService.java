package com.nn2.docker_audit_api.securityengineer.docker;

import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.nio.file.Files;
import java.nio.file.Path;
import java.net.URI;

import org.springframework.stereotype.Service;

import com.github.dockerjava.api.command.InspectContainerResponse;
import com.github.dockerjava.api.model.Container;
import com.nn2.docker_audit_api.securityengineer.config.DockerAuditProperties;
import com.nn2.docker_audit_api.securityengineer.docker.model.ContainerPortSnapshot;
import com.nn2.docker_audit_api.securityengineer.docker.model.ContainerSnapshot;

@Service
public class DockerClientService {

	private static final String DOCKER_SOCKET_PATH = "/var/run/docker.sock";
	private static final String DOCKER_HOST_UNIX_SOCKET = "unix:///var/run/docker.sock";

	private final DockerClientFactory dockerClientFactory;
	private final DockerAuditProperties dockerAuditProperties;

	public DockerClientService(DockerClientFactory dockerClientFactory, DockerAuditProperties dockerAuditProperties) {
		this.dockerClientFactory = dockerClientFactory;
		this.dockerAuditProperties = dockerAuditProperties;
	}

	public List<ContainerSnapshot> listContainerSnapshots(String hostUrl) {
		String effectiveHost = (hostUrl == null || hostUrl.isBlank())
			? dockerAuditProperties.getDefaultHostUrl()
			: hostUrl;

		List<String> candidates = resolveHostCandidates(effectiveHost);
		List<String> failures = new ArrayList<>();

		for (String candidate : candidates) {
			if (isUnixHost(candidate) && !unixSocketExists(candidate)) {
				failures.add(candidate + " -> сокет не найден");
				continue;
			}

			try {
				return querySnapshots(candidate);
			} catch (Exception ex) {
				failures.add(candidate + " -> " + summarizeException(ex));
			}
		}

		String message = "Не удалось подключиться к Docker-хосту. Проверенные варианты: " + String.join("; ", failures);
		throw new DockerConnectionException(message, new IllegalStateException(message));
	}

	private List<ContainerSnapshot> querySnapshots(String hostUrl) throws Exception {
		try (var client = dockerClientFactory.createClient(
			hostUrl,
			dockerAuditProperties.getConnectTimeout(),
			dockerAuditProperties.getReadTimeout())) {
			List<Container> containers = client.listContainersCmd().withShowAll(true).exec();
			List<ContainerSnapshot> snapshots = new ArrayList<>(containers.size());
			for (Container container : containers) {
				InspectContainerResponse inspect = client.inspectContainerCmd(container.getId()).exec();
				snapshots.add(mapToSnapshot(container, inspect, hostUrl));
			}
			return snapshots;
		}
	}

	private String detectMacDesktopSocketHost() {
		String userHome = System.getProperty("user.home");
		if (userHome == null || userHome.isBlank()) {
			return null;
		}

		Path dockerDesktopSocket = Path.of(userHome, ".docker", "run", "docker.sock");
		if (Files.exists(dockerDesktopSocket)) {
			return "unix://" + dockerDesktopSocket;
		}
		return null;
	}

	private List<String> resolveHostCandidates(String effectiveHost) {
		Set<String> ordered = new LinkedHashSet<>();
		ordered.add(effectiveHost);

		String envHost = System.getenv("DOCKER_HOST");
		if (envHost != null && !envHost.isBlank()) {
			ordered.add(envHost.trim());
		}

		if (DOCKER_HOST_UNIX_SOCKET.equals(effectiveHost)) {
			ordered.add("unix:///private/var/run/docker.sock");

			String macSocketHost = detectMacDesktopSocketHost();
			if (macSocketHost != null) {
				ordered.add(macSocketHost);
			}

			String userHome = System.getProperty("user.home");
			if (userHome != null && !userHome.isBlank()) {
				ordered.add("unix://" + Path.of(userHome, ".colima", "default", "docker.sock"));
			}
		}

		return new ArrayList<>(ordered);
	}

	private boolean isUnixHost(String host) {
		return host != null && host.toLowerCase().startsWith("unix://");
	}

	private boolean unixSocketExists(String host) {
		try {
			URI uri = URI.create(host);
			String path = uri.getPath();
			return path != null && !path.isBlank() && Files.exists(Path.of(path));
		} catch (Exception ignored) {
			return false;
		}
	}

	private String summarizeException(Exception ex) {
		String message = ex.getMessage();
		if (message == null || message.isBlank()) {
			return ex.getClass().getSimpleName();
		}
		return message;
	}

	private ContainerSnapshot mapToSnapshot(Container summary, InspectContainerResponse inspect, String hostUrl) {
		var hostConfig = inspect.getHostConfig();
		var config = inspect.getConfig();
		var state = inspect.getState();

		boolean hasDockerSocketMount = inspect.getMounts() != null
			&& inspect.getMounts().stream().anyMatch(m -> DOCKER_SOCKET_PATH.equals(m.getSource())
				|| DOCKER_SOCKET_PATH.equals(m.getDestination() != null ? m.getDestination().getPath() : null));

		List<ContainerPortSnapshot> ports = new ArrayList<>();
		if (summary.getPorts() != null) {
			for (var port : summary.getPorts()) {
				ports.add(new ContainerPortSnapshot(port.getIp(), port.getPrivatePort(), port.getPublicPort(), port.getType()));
			}
		}

		String firstName = summary.getNames() != null && summary.getNames().length > 0
			? summary.getNames()[0].replaceFirst("^/", "")
			: summary.getId().substring(0, Math.min(12, summary.getId().length()));

		String createdAt = summary.getCreated() != null
			? Instant.ofEpochSecond(summary.getCreated()).atOffset(ZoneOffset.UTC).toString()
			: null;

		return new ContainerSnapshot(
			summary.getId(),
			firstName,
			summary.getImage(),
			summary.getState(),
			summary.getStatus(),
			createdAt,
			hostUrl,
			hostConfig != null && Boolean.TRUE.equals(hostConfig.getPrivileged()),
			hostConfig != null && Boolean.TRUE.equals(hostConfig.getReadonlyRootfs()),
			hostConfig != null ? hostConfig.getNetworkMode() : null,
			hostConfig != null ? hostConfig.getPidMode() : null,
			hostConfig != null ? hostConfig.getIpcMode() : null,
			hostConfig != null ? hostConfig.getUtSMode() : null,
			config != null ? config.getUser() : null,
			state != null && state.getHealth() != null ? state.getHealth().getStatus() : null,
			hostConfig != null ? hostConfig.getMemory() : null,
			hostConfig != null ? hostConfig.getNanoCPUs() : null,
			hasDockerSocketMount,
			ports);
	}
}

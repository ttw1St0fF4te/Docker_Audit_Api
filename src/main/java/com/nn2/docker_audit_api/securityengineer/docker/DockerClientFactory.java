package com.nn2.docker_audit_api.securityengineer.docker;

import java.time.Duration;
import java.net.URI;

import org.springframework.stereotype.Component;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientConfig;
import com.github.dockerjava.core.DockerClientImpl;
import com.github.dockerjava.httpclient5.ApacheDockerHttpClient;
import com.github.dockerjava.transport.DockerHttpClient;
import com.github.dockerjava.zerodep.ZerodepDockerHttpClient;

@Component
public class DockerClientFactory {

	public DockerClient createClient(String hostUrl, Duration connectTimeout, Duration readTimeout) {
		DockerClientConfig clientConfig = DefaultDockerClientConfig.createDefaultConfigBuilder()
			.withDockerHost(hostUrl)
			.build();

		DockerHttpClient httpClient = buildHttpClient(clientConfig.getDockerHost(), connectTimeout, readTimeout);

		return DockerClientImpl.getInstance(clientConfig, httpClient);
	}

	private DockerHttpClient buildHttpClient(URI dockerHost, Duration connectTimeout, Duration readTimeout) {
		String scheme = dockerHost.getScheme();
		if ("unix".equalsIgnoreCase(scheme) || "npipe".equalsIgnoreCase(scheme)) {
			return new ZerodepDockerHttpClient.Builder()
				.dockerHost(dockerHost)
				.connectionTimeout(connectTimeout)
				.responseTimeout(readTimeout)
				.build();
		}

		return new ApacheDockerHttpClient.Builder()
			.dockerHost(dockerHost)
			.connectionTimeout(connectTimeout)
			.responseTimeout(readTimeout)
			.build();
	}
}

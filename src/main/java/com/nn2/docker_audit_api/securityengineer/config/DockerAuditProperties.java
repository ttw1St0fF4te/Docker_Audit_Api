package com.nn2.docker_audit_api.securityengineer.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "app.docker")
public class DockerAuditProperties {

	private String defaultHostUrl = "unix:///var/run/docker.sock";
	private Duration connectTimeout = Duration.ofSeconds(5);
	private Duration readTimeout = Duration.ofSeconds(30);

	public String getDefaultHostUrl() {
		return defaultHostUrl;
	}

	public void setDefaultHostUrl(String defaultHostUrl) {
		this.defaultHostUrl = defaultHostUrl;
	}

	public Duration getConnectTimeout() {
		return connectTimeout;
	}

	public void setConnectTimeout(Duration connectTimeout) {
		this.connectTimeout = connectTimeout;
	}

	public Duration getReadTimeout() {
		return readTimeout;
	}

	public void setReadTimeout(Duration readTimeout) {
		this.readTimeout = readTimeout;
	}
}

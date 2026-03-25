package com.nn2.docker_audit_api.mail.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.nn2.docker_audit_api.mail.config.MailModuleProperties;

@Service
public class MailHealthService {

	private final MailModuleProperties mailProperties;
	private final String smtpHost;
	private final Integer smtpPort;
	private final String smtpUsername;

	public MailHealthService(
			MailModuleProperties mailProperties,
			@Value("${spring.mail.host:}") String smtpHost,
			@Value("${spring.mail.port:0}") Integer smtpPort,
			@Value("${spring.mail.username:}") String smtpUsername) {
		this.mailProperties = mailProperties;
		this.smtpHost = smtpHost;
		this.smtpPort = smtpPort;
		this.smtpUsername = smtpUsername;
	}

	public MailHealthStatus check() {
		boolean configured = smtpHost != null && !smtpHost.isBlank()
			&& smtpPort != null && smtpPort > 0
			&& smtpUsername != null && !smtpUsername.isBlank();

		return new MailHealthStatus(mailProperties.isEnabled(), configured, smtpHost, smtpPort, smtpUsername);
	}

	public record MailHealthStatus(
			boolean enabled,
			boolean configured,
			String host,
			Integer port,
			String username) {
	}
}

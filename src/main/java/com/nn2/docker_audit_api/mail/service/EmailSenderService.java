package com.nn2.docker_audit_api.mail.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.MailException;
import org.springframework.stereotype.Service;

import com.nn2.docker_audit_api.mail.config.MailModuleProperties;

@Service
public class EmailSenderService {

	private static final Logger log = LoggerFactory.getLogger(EmailSenderService.class);
	private static final int MAX_ATTEMPTS = 3;

	private final JavaMailSender mailSender;
	private final MailModuleProperties mailProperties;

	public EmailSenderService(JavaMailSender mailSender, MailModuleProperties mailProperties) {
		this.mailSender = mailSender;
		this.mailProperties = mailProperties;
	}

	public boolean sendPlainText(String to, String subject, String body) {
		if (!mailProperties.isEnabled()) {
			log.info("Email disabled. Skipping send to {} with subject '{}'", to, subject);
			return false;
		}

		SimpleMailMessage message = new SimpleMailMessage();
		message.setTo(to);
		message.setSubject(subject);
		message.setText(body);
		message.setFrom(mailProperties.getFrom());

		for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
			try {
				mailSender.send(message);
				return true;
			} catch (MailException ex) {
				boolean lastAttempt = attempt == MAX_ATTEMPTS;
				if (lastAttempt) {
					log.error("Failed to send email to {} after {} attempts", to, MAX_ATTEMPTS, ex);
					throw ex;
				}
				log.warn("SMTP send attempt {} failed for {}. Retrying...", attempt, to);
			}
		}

		return false;
	}
}

package com.nn2.docker_audit_api.mail.dto;

public record MailTestResponse(
		boolean sent,
		String message) {
}

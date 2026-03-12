package com.nn2.docker_audit_api.config;

import java.util.Map;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

@RestControllerAdvice
public class ApiExceptionHandler {

	@ExceptionHandler(ResponseStatusException.class)
	ResponseEntity<Map<String, String>> handleResponseStatus(ResponseStatusException exception) {
		HttpStatusCode status = exception.getStatusCode();
		String message = exception.getReason() != null ? exception.getReason() : "Request failed";
		return ResponseEntity.status(status).body(Map.of("message", message));
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	ResponseEntity<Map<String, String>> handleValidation(MethodArgumentNotValidException exception) {
		String message = exception.getBindingResult().getFieldErrors().stream()
			.findFirst()
			.map(error -> error.getDefaultMessage() != null ? error.getDefaultMessage() : "Validation failed")
			.orElse("Validation failed");
		return ResponseEntity.badRequest().body(Map.of("message", message));
	}
}
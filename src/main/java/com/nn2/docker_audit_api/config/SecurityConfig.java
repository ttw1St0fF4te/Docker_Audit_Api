package com.nn2.docker_audit_api.config;

import java.io.IOException;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nn2.docker_audit_api.auth.jwt.JwtAuthenticationFilter;
import com.nn2.docker_audit_api.auth.model.RoleCode;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	private final ObjectMapper objectMapper;
	private final JwtAuthenticationFilter jwtAuthenticationFilter;

	public SecurityConfig(ObjectMapper objectMapper, JwtAuthenticationFilter jwtAuthenticationFilter) {
		this.objectMapper = objectMapper;
		this.jwtAuthenticationFilter = jwtAuthenticationFilter;
	}

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http
			.csrf(AbstractHttpConfigurer::disable)
			.authorizeHttpRequests(authorize -> authorize
				.requestMatchers("/error", "/api/health", "/api/auth/login").permitAll()
				.requestMatchers("/api/auth/me", "/api/auth/logout").authenticated()
				.requestMatchers("/api/security/**")
					.hasAnyRole(RoleCode.SECURITY_ENGINEER.name(), RoleCode.SUPER_ADMIN.name())
				.requestMatchers("/api/pages/security-engineer").hasRole(RoleCode.SECURITY_ENGINEER.name())
				.requestMatchers("/api/pages/developer").hasRole(RoleCode.DEVELOPER.name())
				.requestMatchers("/api/pages/super-admin").hasRole(RoleCode.SUPER_ADMIN.name())
				.anyRequest().authenticated())
			.httpBasic(AbstractHttpConfigurer::disable)
			.formLogin(AbstractHttpConfigurer::disable)
			.logout(AbstractHttpConfigurer::disable)
			.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.cors(Customizer.withDefaults())
			.exceptionHandling(exceptionHandling -> exceptionHandling
				.authenticationEntryPoint(jsonEntryPoint(HttpStatus.UNAUTHORIZED, "Требуется авторизация"))
				.accessDeniedHandler((request, response, exception) ->
					writeJsonError(response, HttpStatus.FORBIDDEN, "Доступ запрещен")))
			.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
			.build();
	}

	@Bean
	org.springframework.security.authentication.AuthenticationManager authenticationManager(
			AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	private AuthenticationEntryPoint jsonEntryPoint(HttpStatus status, String message) {
		return (request, response, exception) -> writeJsonError(response, status, message);
	}

	private void writeJsonError(HttpServletResponse response, HttpStatus status, String message) throws IOException {
		response.setStatus(status.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		objectMapper.writeValue(response.getOutputStream(), Map.of("message", message));
	}
}
package com.nn2.docker_audit_api.auth.jwt;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import com.nn2.docker_audit_api.auth.entity.AppUser;
import com.nn2.docker_audit_api.auth.model.RoleCode;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

	private static final String CLAIM_UID = "uid";
	private static final String CLAIM_ROLE = "role";
	private static final String CLAIM_FULL_NAME = "fullName";

	private final String issuer;
	private final Duration ttl;
	private final SecretKey secretKey;

	public JwtService(
			@Value("${app.security.jwt.issuer}") String issuer,
			@Value("${app.security.jwt.secret}") String secret,
			@Value("${app.security.jwt.ttl}") Duration ttl) {
		this.issuer = issuer;
		this.ttl = ttl;
		this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
	}

	public JwtToken createToken(AppUser user) {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(ttl);

		String token = Jwts.builder()
			.subject(user.getUsername())
			.issuer(issuer)
			.issuedAt(Date.from(issuedAt))
			.expiration(Date.from(expiresAt))
			.claim(CLAIM_UID, user.getId())
			.claim(CLAIM_ROLE, user.getRole().getCode().name())
			.claim(CLAIM_FULL_NAME, user.getDisplayName())
			.signWith(secretKey)
			.compact();

		return new JwtToken(token, expiresAt);
	}

	public JwtAuthentication parseToken(String token) {
		Claims claims = Jwts.parser()
			.verifyWith(secretKey)
			.requireIssuer(issuer)
			.build()
			.parseSignedClaims(token)
			.getPayload();

		RoleCode role = RoleCode.valueOf(claims.get(CLAIM_ROLE, String.class));
		Long userId = claims.get(CLAIM_UID, Long.class);
		String fullName = claims.get(CLAIM_FULL_NAME, String.class);
		String username = claims.getSubject();

		JwtPrincipal principal = new JwtPrincipal(userId, username, fullName, role);
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + role.name());
		Instant expiresAt = claims.getExpiration().toInstant();

		return new JwtAuthentication(principal, authority, expiresAt);
	}

	public record JwtToken(String value, Instant expiresAt) {
	}

	public record JwtAuthentication(JwtPrincipal principal, SimpleGrantedAuthority authority, Instant expiresAt) {
	}
}
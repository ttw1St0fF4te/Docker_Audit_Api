package com.nn2.docker_audit_api.service;

import java.time.Instant;
import java.util.Map;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
public class InfrastructureHealthService {

	private final DataSource postgresDataSource;
	private final DataSource clickHouseDataSource;

	public InfrastructureHealthService(
			@Qualifier("dataSource") DataSource postgresDataSource,
			@Qualifier("clickHouseDataSource") DataSource clickHouseDataSource) {
		this.postgresDataSource = postgresDataSource;
		this.clickHouseDataSource = clickHouseDataSource;
	}

	public HealthResponse check() {
		DatabaseStatus postgres = probe(postgresDataSource, "PostgreSQL");
		DatabaseStatus clickhouse = probe(clickHouseDataSource, "ClickHouse");
		String overallStatus = postgres.status().equals("UP") && clickhouse.status().equals("UP")
			? "UP"
			: "DEGRADED";

		return new HealthResponse(
			overallStatus,
			"docker-audit-api",
			Instant.now().toString(),
			Map.of(
				"postgres", postgres,
				"clickhouse", clickhouse));
	}

	private DatabaseStatus probe(DataSource dataSource, String label) {
		try (var connection = dataSource.getConnection()) {
			var metadata = connection.getMetaData();
			String details = metadata.getDatabaseProductName() + " " + metadata.getDatabaseProductVersion();
			return new DatabaseStatus("UP", label + " connected", details);
		} catch (Exception exception) {
			return new DatabaseStatus("DOWN", label + " unavailable", exception.getMessage());
		}
	}

	public record HealthResponse(
			String status,
			String service,
			String timestamp,
			Map<String, DatabaseStatus> databases) {
	}

	public record DatabaseStatus(String status, String message, String details) {
	}
}
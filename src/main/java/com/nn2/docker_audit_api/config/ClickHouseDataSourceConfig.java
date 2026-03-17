package com.nn2.docker_audit_api.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

@Configuration
public class ClickHouseDataSourceConfig {

	@Bean
	@Primary
	@ConfigurationProperties("spring.datasource")
	DataSourceProperties postgresDataSourceProperties() {
		return new DataSourceProperties();
	}

	@Bean(name = "dataSource")
	@Primary
	DataSource postgresDataSource(
			@Qualifier("postgresDataSourceProperties") DataSourceProperties properties) {
		return properties.initializeDataSourceBuilder().build();
	}

	@Bean
	@Primary
	JdbcTemplate jdbcTemplate(@Qualifier("dataSource") DataSource dataSource) {
		return new JdbcTemplate(dataSource);
	}

	@Bean
	@ConfigurationProperties("app.clickhouse")
	DataSourceProperties clickHouseDataSourceProperties() {
		return new DataSourceProperties();
	}

	@Bean
	DataSource clickHouseDataSource(
			@Qualifier("clickHouseDataSourceProperties") DataSourceProperties properties) {
		DriverManagerDataSource dataSource = new DriverManagerDataSource();
		dataSource.setDriverClassName(properties.getDriverClassName());
		dataSource.setUrl(properties.getUrl());
		dataSource.setUsername(properties.getUsername());
		dataSource.setPassword(properties.getPassword());
		return dataSource;
	}

	@Bean
	JdbcTemplate clickHouseJdbcTemplate(@Qualifier("clickHouseDataSource") DataSource dataSource) {
		return new JdbcTemplate(dataSource);
	}
}
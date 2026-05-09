package com.nn2.docker_audit_api.securityengineer.service;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nn2.docker_audit_api.securityengineer.docker.model.ContainerSnapshot;
import com.nn2.docker_audit_api.securityengineer.entity.CveScanEntity;
import com.nn2.docker_audit_api.securityengineer.entity.DockerHostEntity;
import com.nn2.docker_audit_api.securityengineer.repository.CveScanRepository;
import com.nn2.docker_audit_api.securityengineer.repository.DockerHostRepository;
import com.nn2.docker_audit_api.securityengineer.docker.DockerClientService;

@Service
public class CveScannerService {

    private static final Logger log = LoggerFactory.getLogger(CveScannerService.class);

    private final CveScanRepository cveScanRepository;
    private final DockerHostRepository dockerHostRepository;
    private final DockerClientService dockerClientService;
    private final JdbcTemplate clickHouseJdbcTemplate;
    private final ObjectMapper objectMapper;

    public CveScannerService(
            CveScanRepository cveScanRepository,
            DockerHostRepository dockerHostRepository,
            DockerClientService dockerClientService,
            @Qualifier("clickHouseJdbcTemplate") JdbcTemplate clickHouseJdbcTemplate,
            ObjectMapper objectMapper) {
        this.cveScanRepository = cveScanRepository;
        this.dockerHostRepository = dockerHostRepository;
        this.dockerClientService = dockerClientService;
        this.clickHouseJdbcTemplate = clickHouseJdbcTemplate;
        this.objectMapper = objectMapper;
    }

    public CveExecutionResult runCveScan(Long hostId, Long startedBy) {
        CveScanEntity running = createRunningScan(hostId, startedBy);

        try {
            List<String> imageRefs = listImageRefsForHost(hostId);
            List<CveVulnerabilityRow> rows = scanImagesWithTrivy(imageRefs, hostId, running.getId());
            writeRowsToClickHouse(rows);
            CveScanEntity completed = completeScan(running.getId(), rows, imageRefs.size());
            return new CveExecutionResult(completed, null);
        } catch (Exception ex) {
            log.error("CVE scan failed: scanId={}, hostId={}", running.getId(), hostId, ex);
            CveScanEntity failed = failScan(running.getId());
            return new CveExecutionResult(failed, ex.getMessage());
        }
    }

    private CveScanEntity createRunningScan(Long hostId, Long startedBy) {
        DockerHostEntity host = dockerHostRepository.findByIdAndActiveTrueAndDeletedFalse(hostId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Активный Docker-хост не найден"));

        CveScanEntity scan = new CveScanEntity();
        scan.setHostId(host.getId());
        scan.setStartedBy(startedBy);
        scan.setStartedAt(Instant.now());
        scan.setStatus("RUNNING");
        scan.setTotalImages(0);
        scan.setTotalVulnerabilities(0);
        scan.setCriticalCount(0);
        scan.setHighCount(0);
        scan.setMediumCount(0);
        scan.setLowCount(0);
        scan.setUnknownCount(0);
        return cveScanRepository.save(scan);
    }

    private CveScanEntity completeScan(Long scanId, List<CveVulnerabilityRow> rows, int imageCount) {
        CveScanEntity scan = cveScanRepository.findById(scanId)
            .orElseThrow(() -> new IllegalStateException("CVE scan not found: " + scanId));

        scan.setFinishedAt(Instant.now());
        scan.setStatus("COMPLETED");
        scan.setTotalImages(imageCount);
        scan.setTotalVulnerabilities(rows.size());
        scan.setCriticalCount(countBySeverity(rows, "CRITICAL"));
        scan.setHighCount(countBySeverity(rows, "HIGH"));
        scan.setMediumCount(countBySeverity(rows, "MEDIUM"));
        scan.setLowCount(countBySeverity(rows, "LOW"));
        scan.setUnknownCount(countBySeverity(rows, "UNKNOWN"));
        return cveScanRepository.save(scan);
    }

    private CveScanEntity failScan(Long scanId) {
        CveScanEntity scan = cveScanRepository.findById(scanId)
            .orElseThrow(() -> new IllegalStateException("CVE scan not found: " + scanId));

        scan.setFinishedAt(Instant.now());
        scan.setStatus("FAILED");
        return cveScanRepository.save(scan);
    }

    private int countBySeverity(List<CveVulnerabilityRow> rows, String severity) {
        int count = 0;
        for (CveVulnerabilityRow row : rows) {
            if (severity.equalsIgnoreCase(row.severity())) {
                count++;
            }
        }
        return count;
    }

    private List<String> listImageRefsForHost(Long hostId) {
        DockerHostEntity host = dockerHostRepository.findByIdAndActiveTrueAndDeletedFalse(hostId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Активный Docker-хост не найден"));

        List<ContainerSnapshot> snapshots = dockerClientService.listContainerSnapshots(host.getBaseUrl());
        List<String> imageRefs = new ArrayList<>();
        for (ContainerSnapshot snapshot : snapshots) {
            String image = snapshot.image();
            if (image != null && !image.isBlank() && !imageRefs.contains(image)) {
                imageRefs.add(image);
            }
        }
        return imageRefs;
    }

    private List<CveVulnerabilityRow> scanImagesWithTrivy(List<String> imageRefs, Long hostId, Long scanId) {
        List<CveVulnerabilityRow> rows = new ArrayList<>();
        for (String imageRef : imageRefs) {
            JsonNode root = runTrivyScan(imageRef);
            rows.addAll(extractRows(root, imageRef, hostId, scanId));
        }
        return rows;
    }

    private JsonNode runTrivyScan(String imageRef) {
        List<String> command = List.of(
            "docker-compose",
            "exec",
            "-T",
            "trivy",
            "trivy",
            "image",
            "--server",
            "http://localhost:4954",
            "--scanners",
            "vuln",
            "--quiet",
            "--format",
            "json",
            "--severity",
            "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
            imageRef
        );

        try {
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.redirectErrorStream(true);
            Process process = builder.start();
            String output = readProcessOutput(process.getInputStream());
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new IllegalStateException("Trivy scan failed for " + imageRef + ": " + output);
            }
            if (output == null || output.isBlank()) {
                return objectMapper.createObjectNode();
            }
            return objectMapper.readTree(output);
        } catch (IllegalStateException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalStateException("Trivy scan failed for " + imageRef + ": " + ex.getMessage(), ex);
        }
    }

    private String readProcessOutput(InputStream inputStream) throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[4096];
        int read;
        while ((read = inputStream.read(data)) != -1) {
            buffer.write(data, 0, read);
        }
        return buffer.toString();
    }

    private List<CveVulnerabilityRow> extractRows(JsonNode root, String imageRef, Long hostId, Long scanId) {
        List<CveVulnerabilityRow> rows = new ArrayList<>();
        JsonNode results = root.path("Results");
        if (!results.isArray()) {
            return rows;
        }

        Instant scannedAt = Instant.now();
        for (JsonNode result : results) {
            JsonNode vulnerabilities = result.path("Vulnerabilities");
            if (!vulnerabilities.isArray()) {
                continue;
            }

            for (JsonNode vuln : vulnerabilities) {
                String vulnerabilityId = textOrDefault(vuln, "VulnerabilityID", "UNKNOWN");
                String severity = textOrDefault(vuln, "Severity", "UNKNOWN");
                String title = textOrDefault(vuln, "Title", vulnerabilityId);
                String installedVersion = textOrDefault(vuln, "InstalledVersion", "-");
                String fixedVersion = textOrDefault(vuln, "FixedVersion", null);
                String primaryUrl = textOrDefault(vuln, "PrimaryURL", "");

                rows.add(new CveVulnerabilityRow(
                    scanId,
                    hostId,
                    imageRef,
                    imageRef,
                    vulnerabilityId,
                    title,
                    severity,
                    installedVersion,
                    fixedVersion,
                    primaryUrl,
                    scannedAt));
            }
        }

        return rows;
    }

    private String textOrDefault(JsonNode node, String field, String fallback) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) {
            return fallback;
        }
        String text = value.asText();
        return text == null || text.isBlank() ? fallback : text;
    }

    private void writeRowsToClickHouse(List<CveVulnerabilityRow> rows) {
        if (rows.isEmpty()) {
            return;
        }

        String sql = """
            INSERT INTO audit_analytics.cve_vulnerabilities_log (
                scan_id,
                host_id,
                image_id,
                image_name,
                vulnerability_id,
                vulnerability_title,
                severity,
                affected_version,
                fixed_version,
                advisory_url,
                scan_timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;

        for (CveVulnerabilityRow row : rows) {
            clickHouseJdbcTemplate.update(
                sql,
                row.scanId(),
                row.hostId(),
                row.imageId(),
                row.imageName(),
                row.vulnerabilityId(),
                row.vulnerabilityTitle(),
                row.severity(),
                row.affectedVersion(),
                row.fixedVersion(),
                row.advisoryUrl(),
                Timestamp.from(row.scanTimestamp()));
        }
    }

    public record CveExecutionResult(CveScanEntity scan, String errorMessage) {
    }

    private record CveVulnerabilityRow(
            Long scanId,
            Long hostId,
            String imageId,
            String imageName,
            String vulnerabilityId,
            String vulnerabilityTitle,
            String severity,
            String affectedVersion,
            String fixedVersion,
            String advisoryUrl,
            Instant scanTimestamp) {
    }
}

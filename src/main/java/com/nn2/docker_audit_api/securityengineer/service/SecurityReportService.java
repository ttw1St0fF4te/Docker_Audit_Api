package com.nn2.docker_audit_api.securityengineer.service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.nn2.docker_audit_api.securityengineer.dto.analytics.AnalyticsOverviewResponse;
import com.nn2.docker_audit_api.securityengineer.dto.analytics.SecurityScoreTrendPointResponse;
import com.nn2.docker_audit_api.securityengineer.dto.analytics.SecurityScoreTrendResponse;
import com.nn2.docker_audit_api.securityengineer.dto.analytics.SeverityTrendPointResponse;
import com.nn2.docker_audit_api.securityengineer.dto.analytics.SeverityTrendResponse;
import com.nn2.docker_audit_api.securityengineer.dto.analytics.TopHostRiskItemResponse;
import com.nn2.docker_audit_api.securityengineer.dto.analytics.TopHostRiskResponse;
import com.nn2.docker_audit_api.securityengineer.dto.analytics.TopRuleItemResponse;
import com.nn2.docker_audit_api.securityengineer.dto.analytics.TopRulesResponse;

@Service
public class SecurityReportService {

    private static final DateTimeFormatter FILE_TS = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
        .withZone(ZoneId.systemDefault());

    private static final String FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf";

    private final SecurityAnalyticsService cisAnalyticsService;
    private final CveAnalyticsService cveAnalyticsService;

    public SecurityReportService(SecurityAnalyticsService cisAnalyticsService, CveAnalyticsService cveAnalyticsService) {
        this.cisAnalyticsService = cisAnalyticsService;
        this.cveAnalyticsService = cveAnalyticsService;
    }

    public ReportResult generate(
            String scopeRaw,
            String formatRaw,
            String scanTypeRaw,
            String from,
            String to,
            String bucket,
            Long hostId) {
        Scope scope = parseScope(scopeRaw);
        Format format = parseFormat(formatRaw);
        ScanType scanType = parseScanType(scanTypeRaw);

        ReportData report = collectReportData(scope, scanType, from, to, bucket, hostId);

        String timestamp = FILE_TS.format(Instant.now());
        String extension = format == Format.CSV ? "csv" : "pdf";
        String fileName = "otchet-bezopasnosti-" + scanType.name().toLowerCase() + "-" + scope.name().toLowerCase(Locale.ROOT) + "-" + timestamp + "." + extension;

        try {
            byte[] content;
            String contentType;
            if (format == Format.CSV) {
                content = buildCsv(report).getBytes(StandardCharsets.UTF_8);
                contentType = "text/csv;charset=utf-8";
            } else {
                content = buildPdf(report);
                contentType = "application/pdf";
            }
            return new ReportResult(fileName, contentType, content);
        } catch (IOException ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Ошибка формирования отчета: " + ex.getMessage());
        }
    }

    private ReportData collectReportData(Scope scope, ScanType scanType, String from, String to, String bucket, Long hostId) {
        AnalyticsOverviewResponse overview = null;
        SeverityTrendResponse severityTrend = null;
        SecurityScoreTrendResponse scoreTrend = null;
        TopHostRiskResponse topHosts = null;
        TopRulesResponse topRules = null;

        if (scanType == ScanType.CVE) {
            if (scope == Scope.ALL || scope == Scope.OVERVIEW) {
                overview = cveAnalyticsService.getOverview(from, to, hostId);
            }
            if (scope == Scope.ALL || scope == Scope.SEVERITY_TREND) {
                severityTrend = cveAnalyticsService.getSeverityTrend(from, to, bucket, hostId);
            }
            if (scope == Scope.ALL || scope == Scope.SECURITY_SCORE_TREND) {
                scoreTrend = cveAnalyticsService.getSecurityScoreTrend(from, to, bucket, hostId);
            }
            if (scope == Scope.ALL || scope == Scope.TOP_HOSTS) {
                topHosts = cveAnalyticsService.getTopHosts(from, to, 10);
            }
            if (scope == Scope.ALL || scope == Scope.TOP_RULES) {
                topRules = cveAnalyticsService.getTopRules(from, to, 10, hostId);
            }
        } else {
            if (scope == Scope.ALL || scope == Scope.OVERVIEW) {
                overview = cisAnalyticsService.getOverview(from, to, hostId);
            }
            if (scope == Scope.ALL || scope == Scope.SEVERITY_TREND) {
                severityTrend = cisAnalyticsService.getSeverityTrend(from, to, bucket, hostId);
            }
            if (scope == Scope.ALL || scope == Scope.SECURITY_SCORE_TREND) {
                scoreTrend = cisAnalyticsService.getSecurityScoreTrend(from, to, bucket, hostId);
            }
            if (scope == Scope.ALL || scope == Scope.TOP_HOSTS) {
                topHosts = cisAnalyticsService.getTopHosts(from, to, 10);
            }
            if (scope == Scope.ALL || scope == Scope.TOP_RULES) {
                topRules = cisAnalyticsService.getTopRules(from, to, 10, hostId);
            }
        }

        return new ReportData(scope, overview, severityTrend, scoreTrend, topHosts, topRules, scanType);
    }

    private String buildCsv(ReportData data) {
        StringBuilder sb = new StringBuilder();
        sb.append("Отчет по безопасности Docker (").append(data.scanType.name()).append(")").append('\n');
        sb.append("Раздел,").append(data.scope.name()).append('\n');
        sb.append("Сформирован,").append(Instant.now()).append('\n');
        sb.append('\n');

        if (data.overview != null) {
            sb.append("[Сводная аналитика]").append('\n');
            sb.append("Всего сканов,Всего проверок,Непройдено,CRITICAL,HIGH,MEDIUM,LOW,Индекс защищенности").append('\n');
            sb.append(data.overview.totalScans()).append(',')
                .append(data.overview.totalChecks()).append(',')
                .append(data.overview.totalFailed()).append(',')
                .append(data.overview.criticalCount()).append(',')
                .append(data.overview.highCount()).append(',')
                .append(data.overview.mediumCount()).append(',')
                .append(data.overview.lowCount()).append(',')
                .append(data.overview.securityScore())
                .append('\n').append('\n');
        }

        if (data.severityTrend != null) {
            sb.append("[Динамика нарушений по severity]").append('\n');
            sb.append("Период,CRITICAL,HIGH,MEDIUM,LOW,Непройдено").append('\n');
            for (SeverityTrendPointResponse item : data.severityTrend.items()) {
                sb.append(item.bucketStart()).append(',')
                    .append(item.critical()).append(',')
                    .append(item.high()).append(',')
                    .append(item.medium()).append(',')
                    .append(item.low()).append(',')
                    .append(item.totalFailed()).append('\n');
            }
            sb.append('\n');
        }

        if (data.scoreTrend != null) {
            sb.append("[Динамика индекса защищенности]").append('\n');
            sb.append("Период,Индекс защищенности,Всего проверок,Непройдено").append('\n');
            for (SecurityScoreTrendPointResponse item : data.scoreTrend.items()) {
                sb.append(item.bucketStart()).append(',')
                    .append(item.securityScore()).append(',')
                    .append(item.totalChecks()).append(',')
                    .append(item.totalFailed()).append('\n');
            }
            sb.append('\n');
        }

        if (data.topHosts != null) {
            sb.append("[Топ проблемных хостов]").append('\n');
            sb.append("Host ID,Название,Сканов,Непройдено,CRITICAL,HIGH,MEDIUM,LOW,Индекс").append('\n');
            for (TopHostRiskItemResponse item : data.topHosts.items()) {
                sb.append(item.hostId()).append(',')
                    .append(escapeCsv(item.hostName())).append(',')
                    .append(item.scans()).append(',')
                    .append(item.totalFailed()).append(',')
                    .append(item.criticalCount()).append(',')
                    .append(item.highCount()).append(',')
                    .append(item.mediumCount()).append(',')
                    .append(item.lowCount()).append(',')
                    .append(item.securityScore()).append('\n');
            }
            sb.append('\n');
        }

        if (data.topRules != null) {
            sb.append("[Топ провальных правил]").append('\n');
            sb.append("Код правила,Название,Непройдено,Сканов,Контейнеров").append('\n');
            for (TopRuleItemResponse item : data.topRules.items()) {
                sb.append(escapeCsv(item.ruleCode())).append(',')
                    .append(escapeCsv(item.ruleName())).append(',')
                    .append(item.failedCount()).append(',')
                    .append(item.affectedScans()).append(',')
                    .append(item.affectedContainers()).append('\n');
            }
        }

        return sb.toString();
    }

    private byte[] buildPdf(ReportData report) throws IOException {
        List<String> lines = buildPdfLines(report);

        try (PDDocument document = new PDDocument(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            Path fontPath = Path.of(FONT_PATH);
            if (!Files.exists(fontPath)) {
                throw new IOException("Шрифт DejaVuSans не найден: " + FONT_PATH);
            }
            
            PDType0Font font;
            try (InputStream fontStream = Files.newInputStream(fontPath)) {
                font = PDType0Font.load(document, fontStream);
            }

            PDPage page = new PDPage();
            document.addPage(page);
            PDPageContentStream content = new PDPageContentStream(document, page);

            float margin = 50f;
            float y = 770f;
            float leading = 14f;

            for (String line : lines) {
                if (y < 60f) {
                    content.close();
                    page = new PDPage();
                    document.addPage(page);
                    content = new PDPageContentStream(document, page);
                    y = 770f;
                }

                content.beginText();
                content.setFont(font, 11);
                content.newLineAtOffset(margin, y);
                content.showText(line);
                content.endText();
                y -= leading;
            }

            content.close();
            document.save(out);
            return out.toByteArray();
        }
    }

    private List<String> buildPdfLines(ReportData data) {
        List<String> lines = new ArrayList<>();
        lines.add("Отчет по безопасности Docker (" + data.scanType.name() + ")");
        lines.add("Раздел: " + data.scope.name());
        lines.add("Сформирован: " + Instant.now());
        lines.add("");

        if (data.overview != null) {
            lines.add("Сводная аналитика:");
            lines.add("Всего сканов: " + data.overview.totalScans());
            lines.add("Всего проверок: " + data.overview.totalChecks());
            lines.add("Непройдено: " + data.overview.totalFailed());
            lines.add("CRITICAL/HIGH/MEDIUM/LOW: "
                + data.overview.criticalCount() + "/"
                + data.overview.highCount() + "/"
                + data.overview.mediumCount() + "/"
                + data.overview.lowCount());
            lines.add("Индекс защищенности: " + data.overview.securityScore());
            lines.add("");
        }

        if (data.severityTrend != null) {
            lines.add("Динамика нарушений по severity:");
            for (SeverityTrendPointResponse item : data.severityTrend.items()) {
                lines.add(item.bucketStart() + " | C=" + item.critical() + " H=" + item.high()
                    + " M=" + item.medium() + " L=" + item.low() + " F=" + item.totalFailed());
            }
            lines.add("");
        }

        if (data.scoreTrend != null) {
            lines.add("Динамика индекса защищенности:");
            for (SecurityScoreTrendPointResponse item : data.scoreTrend.items()) {
                lines.add(item.bucketStart() + " | индекс=" + item.securityScore()
                    + " проверок=" + item.totalChecks() + " непройдено=" + item.totalFailed());
            }
            lines.add("");
        }

        if (data.topHosts != null) {
            lines.add("Топ проблемных хостов:");
            for (TopHostRiskItemResponse item : data.topHosts.items()) {
                lines.add("#" + item.hostId() + " " + item.hostName() + " | сканов=" + item.scans()
                    + " непройдено=" + item.totalFailed() + " индекс=" + item.securityScore());
            }
            lines.add("");
        }

        if (data.topRules != null) {
            lines.add("Топ провальных правил:");
            for (TopRuleItemResponse item : data.topRules.items()) {
                lines.add(item.ruleCode() + " " + item.ruleName() + " | непройдено=" + item.failedCount()
                    + " сканов=" + item.affectedScans() + " контейнеров=" + item.affectedContainers());
            }
        }

        return lines;
    }

    private String escapeCsv(String value) {
        if (value == null) {
            return "";
        }
        String escaped = value.replace("\"", "\"\"");
        return '"' + escaped + '"';
    }

    private Scope parseScope(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "scope обязателен");
        }
        try {
            return Scope.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "scope должен быть ALL, OVERVIEW, SEVERITY_TREND, SECURITY_SCORE_TREND, TOP_HOSTS или TOP_RULES");
        }
    }

    private Format parseFormat(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "format обязателен");
        }
        try {
            return Format.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "format должен быть PDF или CSV");
        }
    }

    private ScanType parseScanType(String raw) {
        if (raw == null || raw.isBlank()) {
            return ScanType.CIS;
        }
        try {
            return ScanType.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "scanType должен быть CIS или CVE");
        }
    }

    private enum Scope {
        ALL,
        OVERVIEW,
        SEVERITY_TREND,
        SECURITY_SCORE_TREND,
        TOP_HOSTS,
        TOP_RULES
    }

    private enum Format {
        PDF,
        CSV
    }

    private enum ScanType {
        CIS,
        CVE
    }

    private record ReportData(
            Scope scope,
            AnalyticsOverviewResponse overview,
            SeverityTrendResponse severityTrend,
            SecurityScoreTrendResponse scoreTrend,
            TopHostRiskResponse topHosts,
            TopRulesResponse topRules,
            ScanType scanType) {
    }

    public record ReportResult(String fileName, String contentType, byte[] content) {
    }
}

package com.nn2.docker_audit_api.securityengineer.service;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.nn2.docker_audit_api.securityengineer.docker.DockerClientService;
import com.nn2.docker_audit_api.securityengineer.docker.model.ContainerSnapshot;
import com.nn2.docker_audit_api.securityengineer.dto.CisRuleCheckResultResponse;
import com.nn2.docker_audit_api.securityengineer.dto.ContainerCisAuditResponse;
import com.nn2.docker_audit_api.securityengineer.entity.CisRuleEntity;
import com.nn2.docker_audit_api.securityengineer.repository.CisRuleRepository;
import com.nn2.docker_audit_api.securityengineer.rules.CisCheckRule;
import com.nn2.docker_audit_api.securityengineer.rules.CisRuleCatalog;

@Service
public class CisRuleEngine {

    private final CisRuleRepository cisRuleRepository;
    private final DockerClientService dockerClientService;
    private final Map<String, CisCheckRule> checksByCode;

    public CisRuleEngine(
            CisRuleRepository cisRuleRepository,
            DockerClientService dockerClientService,
            CisRuleCatalog ruleCatalog) {
        this.cisRuleRepository = cisRuleRepository;
        this.dockerClientService = dockerClientService;
        this.checksByCode = ruleCatalog.all();
    }

    public List<ContainerCisAuditResponse> evaluateActiveRules(String hostUrl) {
        List<CisRuleEntity> activeRules = cisRuleRepository.findByEnabledTrueOrderByCisCodeAsc();
        validateRuleCoverage(activeRules);

        List<ContainerSnapshot> containers = dockerClientService.listContainerSnapshots(hostUrl);
        List<ContainerCisAuditResponse> result = new ArrayList<>(containers.size());

        for (ContainerSnapshot snapshot : containers) {
            List<CisRuleCheckResultResponse> checks = new ArrayList<>(activeRules.size());
            int failed = 0;

            for (CisRuleEntity rule : activeRules) {
                CisCheckRule check = checksByCode.get(rule.getCisCode());
                CisCheckRule.RuleCheckOutcome outcome = check.evaluate(snapshot);
                if (!outcome.passed()) {
                    failed++;
                }

                checks.add(new CisRuleCheckResultResponse(
                    rule.getCisCode(),
                    rule.getName(),
                    rule.getSeverity(),
                    outcome.passed(),
                    outcome.message(),
                    rule.getRecommendation()));
            }

            result.add(new ContainerCisAuditResponse(
                snapshot.containerId(),
                snapshot.containerName(),
                snapshot.image(),
                checks.size() - failed,
                failed,
                checks));
        }

        return result;
    }

    private void validateRuleCoverage(List<CisRuleEntity> activeRules) {
        Set<String> dbRuleCodes = cisRuleRepository.findAll().stream()
            .map(CisRuleEntity::getCisCode)
            .collect(Collectors.toCollection(LinkedHashSet::new));

        Set<String> engineRuleCodes = new LinkedHashSet<>(checksByCode.keySet());

        Set<String> missingInEngine = new LinkedHashSet<>(dbRuleCodes);
        missingInEngine.removeAll(engineRuleCodes);

        Set<String> missingInDb = new LinkedHashSet<>(engineRuleCodes);
        missingInDb.removeAll(dbRuleCodes);

        if (!missingInEngine.isEmpty() || !missingInDb.isEmpty()) {
            throw new IllegalStateException(
                "Несоответствие CIS-правил между БД и движком. "
                    + "Нет в движке: " + missingInEngine + "; нет в БД: " + missingInDb);
        }

        if (activeRules.isEmpty()) {
            throw new IllegalStateException("В БД нет активных CIS-правил для запуска проверки");
        }
    }
}

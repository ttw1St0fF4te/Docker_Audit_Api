package com.nn2.docker_audit_api.securityengineer.rules;

import com.nn2.docker_audit_api.securityengineer.docker.model.ContainerSnapshot;

@FunctionalInterface
public interface CisCheckRule {

    RuleCheckOutcome evaluate(ContainerSnapshot snapshot);

    record RuleCheckOutcome(boolean passed, String message) {
    }
}

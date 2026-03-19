package com.nn2.docker_audit_api.developer.service;

import com.nn2.docker_audit_api.securityengineer.entity.ScanEntity;

public interface NotificationDispatcher {

    void dispatchForCompletedScan(ScanEntity scan);
}

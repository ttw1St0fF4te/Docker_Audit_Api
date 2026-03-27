package com.nn2.docker_audit_api.controller;

import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.nn2.docker_audit_api.admin.dto.AdminDockerHostConnectionTestRequest;
import com.nn2.docker_audit_api.admin.dto.AdminDockerHostConnectionTestResponse;
import com.nn2.docker_audit_api.admin.dto.AdminDockerHostDeleteResponse;
import com.nn2.docker_audit_api.admin.dto.AdminDockerHostUpsertRequest;
import com.nn2.docker_audit_api.admin.service.AdminDockerHostService;
import com.nn2.docker_audit_api.securityengineer.dto.DockerHostItemResponse;
import com.nn2.docker_audit_api.securityengineer.dto.DockerHostsPageResponse;

import jakarta.validation.Valid;

@Validated
@RestController
@RequestMapping("/api/admin/hosts")
public class AdminDockerHostController {

    private final AdminDockerHostService adminDockerHostService;

    public AdminDockerHostController(AdminDockerHostService adminDockerHostService) {
        this.adminDockerHostService = adminDockerHostService;
    }

    @GetMapping
    public DockerHostsPageResponse listHosts(
            @RequestParam(name = "page", required = false) Integer page,
            @RequestParam(name = "size", required = false) Integer size,
            @RequestParam(name = "active", required = false) Boolean active,
            @RequestParam(name = "deleted", required = false) Boolean deleted) {
        return adminDockerHostService.listHosts(page, size, active, deleted);
    }

    @PostMapping("/test-connection")
    public AdminDockerHostConnectionTestResponse testConnection(
            @RequestBody @Valid AdminDockerHostConnectionTestRequest request) {
        return adminDockerHostService.testConnection(request);
    }

    @PostMapping
    public DockerHostItemResponse createHost(@RequestBody @Valid AdminDockerHostUpsertRequest request) {
        return adminDockerHostService.createHost(request);
    }

    @PatchMapping("/{id}")
    public DockerHostItemResponse updateHost(
            @PathVariable("id") Long id,
            @RequestBody @Valid AdminDockerHostUpsertRequest request) {
        return adminDockerHostService.updateHost(id, request);
    }

    @PatchMapping("/{id}/active")
    public DockerHostItemResponse setActive(
            @PathVariable("id") Long id,
            @RequestParam(name = "value") boolean value) {
        return adminDockerHostService.setHostActive(id, value);
    }

    @PostMapping("/{id}/soft-delete")
    public AdminDockerHostDeleteResponse softDelete(@PathVariable("id") Long id) {
        return adminDockerHostService.softDelete(id);
    }

    @PostMapping("/{id}/restore")
    public DockerHostItemResponse restore(@PathVariable("id") Long id) {
        return adminDockerHostService.restore(id);
    }

    @DeleteMapping("/{id}")
    public AdminDockerHostDeleteResponse hardDelete(@PathVariable("id") Long id) {
        return adminDockerHostService.hardDelete(id);
    }
}

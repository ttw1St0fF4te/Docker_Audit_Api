package com.nn2.docker_audit_api.securityengineer.rules;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.springframework.stereotype.Component;

import com.nn2.docker_audit_api.securityengineer.docker.model.ContainerSnapshot;
import com.nn2.docker_audit_api.securityengineer.rules.CisCheckRule.RuleCheckOutcome;

@Component
public class CisRuleCatalog {

    private static final Set<String> DANGEROUS_CAPABILITIES = Set.of(
        "ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_TIME");

    public Map<String, CisCheckRule> all() {
        Map<String, CisCheckRule> rules = new LinkedHashMap<>();

        rules.put("CIS-5.1", snapshot -> {
            boolean unconfined = hasSecurityOpt(snapshot, "apparmor=unconfined");
            return unconfined
                ? fail("Обнаружен AppArmor в режиме unconfined")
                : pass("AppArmor не отключен");
        });

        rules.put("CIS-5.2", snapshot -> {
            boolean selinuxDisabled = hasSecurityOpt(snapshot, "label=disable");
            return selinuxDisabled
                ? fail("SELinux-метки отключены через label=disable")
                : pass("SELinux-метки не отключены");
        });

        rules.put("CIS-5.3", snapshot -> {
            List<String> dangerous = new ArrayList<>();
            for (String capability : snapshot.capAdd()) {
                if (capability != null && DANGEROUS_CAPABILITIES.contains(capability.toUpperCase(Locale.ROOT))) {
                    dangerous.add(capability);
                }
            }
            return dangerous.isEmpty()
                ? pass("Опасные capabilities не добавлены")
                : fail("Добавлены опасные capabilities: " + String.join(", ", dangerous));
        });

        rules.put("CIS-5.4", snapshot -> snapshot.privileged()
            ? fail("Контейнер запущен в привилегированном режиме")
            : pass("Privileged mode не используется"));

        rules.put("CIS-5.5", snapshot -> snapshot.dockerSocketMounted()
            ? fail("Обнаружено монтирование docker.sock внутрь контейнера")
            : pass("Docker socket внутрь контейнера не монтируется"));

        rules.put("CIS-5.6", snapshot -> isHostMode(snapshot.networkMode())
            ? fail("Используется host network mode")
            : pass("Host network mode не используется"));

        rules.put("CIS-5.7", snapshot -> isHostMode(snapshot.pidMode())
            ? fail("Контейнер разделяет PID namespace хоста")
            : pass("PID namespace контейнера изолирован"));

        rules.put("CIS-5.8", snapshot -> isHostMode(snapshot.ipcMode())
            ? fail("Контейнер разделяет IPC namespace хоста")
            : pass("IPC namespace контейнера изолирован"));

        rules.put("CIS-5.9", snapshot -> isHostMode(snapshot.utsMode())
            ? fail("Контейнер разделяет UTS namespace хоста")
            : pass("UTS namespace контейнера изолирован"));

        rules.put("CIS-5.10", snapshot -> snapshot.readOnlyRootFs()
            ? pass("Root filesystem только для чтения")
            : fail("Root filesystem контейнера доступен на запись"));

        rules.put("CIS-5.11", snapshot -> {
            String user = snapshot.user() == null ? "" : snapshot.user().trim();
            boolean root = user.isBlank() || "0".equals(user) || "root".equalsIgnoreCase(user);
            return root
                ? fail("Контейнер работает от root")
                : pass("Контейнер работает от непривилегированного пользователя: " + user);
        });

        rules.put("CIS-5.12", snapshot -> isPositive(snapshot.memoryLimit())
            ? pass("Лимит памяти задан")
            : fail("Лимит памяти не задан"));

        rules.put("CIS-5.13", snapshot -> isPositive(snapshot.nanoCpuLimit())
            ? pass("Лимит CPU задан")
            : fail("Лимит CPU не задан"));

        rules.put("CIS-5.14", snapshot -> {
            String health = normalize(snapshot.healthStatus());
            return health.isEmpty()
                ? fail("Healthcheck не настроен")
                : pass("Healthcheck настроен, статус: " + health);
        });

        rules.put("CIS-5.15", snapshot -> usesLatestTag(snapshot.image())
            ? fail("Используется тег latest")
            : pass("Используется фиксированный тег образа"));

        rules.put("CIS-5.16", snapshot -> {
            String host = normalize(snapshot.hostUrl());
            return host.startsWith("tcp://")
                ? fail("Docker daemon доступен по plain TCP: " + host)
                : pass("Docker daemon не использует plain TCP");
        });

        rules.put("CIS-5.17", snapshot -> {
            boolean dropped = snapshot.capDrop().stream()
                .anyMatch(cap -> "NET_RAW".equalsIgnoreCase(cap));
            return dropped
                ? pass("NET_RAW capability удалена")
                : fail("NET_RAW capability не удалена");
        });

        rules.put("CIS-5.18", snapshot -> {
            boolean unconfined = hasSecurityOpt(snapshot, "seccomp=unconfined");
            return unconfined
                ? fail("Seccomp профиль отключен (unconfined)")
                : pass("Seccomp профиль не отключен");
        });

        rules.put("CIS-5.19", snapshot -> {
            List<String> riskyMounts = snapshot.mountSources().stream()
                .filter(this::isBroadHostMount)
                .toList();
            return riskyMounts.isEmpty()
                ? pass("Критичных широких host mounts не найдено")
                : fail("Обнаружены широкие host mounts: " + String.join(", ", riskyMounts));
        });

        rules.put("CIS-5.20", snapshot -> {
            String restartPolicy = normalize(snapshot.restartPolicyName());
            return "always".equals(restartPolicy)
                ? fail("restart policy always может скрывать crash loops")
                : pass("restart policy не выглядит злоупотребляемой");
        });

        return rules;
    }

    private boolean hasSecurityOpt(ContainerSnapshot snapshot, String expected) {
        String normalizedExpected = expected.toLowerCase(Locale.ROOT);
        return snapshot.securityOptions().stream()
            .filter(value -> value != null && !value.isBlank())
            .map(value -> value.toLowerCase(Locale.ROOT))
            .anyMatch(value -> value.equals(normalizedExpected));
    }

    private boolean isHostMode(String mode) {
        return "host".equals(normalize(mode));
    }

    private boolean isPositive(Long value) {
        return value != null && value > 0;
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private boolean usesLatestTag(String image) {
        if (image == null || image.isBlank()) {
            return false;
        }
        String normalized = image.trim().toLowerCase(Locale.ROOT);
        if (!normalized.contains(":")) {
            return true;
        }
        return normalized.endsWith(":latest");
    }

    private boolean isBroadHostMount(String source) {
        if (source == null || source.isBlank()) {
            return false;
        }

        String normalized = source.trim().toLowerCase(Locale.ROOT);
        List<String> broad = Arrays.asList("/", "/etc", "/var", "/usr", "/opt", "/root", "/home");
        return broad.stream().anyMatch(path -> path.equals(normalized) || normalized.startsWith(path + "/"));
    }

    private RuleCheckOutcome pass(String message) {
        return new RuleCheckOutcome(true, message);
    }

    private RuleCheckOutcome fail(String message) {
        return new RuleCheckOutcome(false, message);
    }
}

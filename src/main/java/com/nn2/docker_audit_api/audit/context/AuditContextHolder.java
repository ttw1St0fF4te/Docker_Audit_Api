package com.nn2.docker_audit_api.audit.context;

import java.util.UUID;
import java.util.function.Supplier;

import org.springframework.stereotype.Component;

@Component
public class AuditContextHolder {

    private static final ThreadLocal<AuditContext> CONTEXT = new ThreadLocal<>();

    public String getRequestId() {
        AuditContext context = CONTEXT.get();
        return context == null ? null : context.requestId();
    }

    public String getActor() {
        AuditContext context = CONTEXT.get();
        return context == null ? null : context.actor();
    }

    public String getOrCreateRequestId() {
        AuditContext current = CONTEXT.get();
        if (current != null && current.requestId() != null && !current.requestId().isBlank()) {
            return current.requestId();
        }

        String generated = UUID.randomUUID().toString();
        String actor = current == null ? null : current.actor();
        CONTEXT.set(new AuditContext(generated, actor));
        return generated;
    }

    public void set(String requestId, String actor) {
        CONTEXT.set(new AuditContext(requestId, actor));
    }

    public void clear() {
        CONTEXT.remove();
    }

    public <T> T runWith(String requestId, String actor, Supplier<T> action) {
        AuditContext previous = CONTEXT.get();
        CONTEXT.set(new AuditContext(requestId, actor));
        try {
            return action.get();
        } finally {
            restore(previous);
        }
    }

    public void runWith(String requestId, String actor, Runnable action) {
        runWith(requestId, actor, () -> {
            action.run();
            return null;
        });
    }

    private void restore(AuditContext previous) {
        if (previous == null) {
            CONTEXT.remove();
            return;
        }
        CONTEXT.set(previous);
    }

    private record AuditContext(String requestId, String actor) {
    }
}

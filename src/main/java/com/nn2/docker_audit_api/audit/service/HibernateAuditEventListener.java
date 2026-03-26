package com.nn2.docker_audit_api.audit.service;

import java.lang.reflect.Method;
import java.time.temporal.Temporal;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import org.hibernate.Hibernate;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.hibernate.event.spi.PostDeleteEvent;
import org.hibernate.event.spi.PostDeleteEventListener;
import org.hibernate.event.spi.PostInsertEvent;
import org.hibernate.event.spi.PostInsertEventListener;
import org.hibernate.event.spi.PostUpdateEvent;
import org.hibernate.event.spi.PostUpdateEventListener;
import org.hibernate.persister.entity.EntityPersister;
import org.hibernate.proxy.HibernateProxy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nn2.docker_audit_api.audit.context.AuditContextHolder;
import com.nn2.docker_audit_api.auth.jwt.JwtPrincipal;

import jakarta.persistence.Table;

@Component
public class HibernateAuditEventListener implements PostInsertEventListener, PostUpdateEventListener, PostDeleteEventListener {

    private static final String AUDIT_TABLE_NAME = "audit_change_log";

    private final AuditLogWriter auditLogWriter;
    private final ObjectMapper objectMapper;
    private final AuditContextHolder auditContextHolder;

    public HibernateAuditEventListener(
            AuditLogWriter auditLogWriter,
            ObjectMapper objectMapper,
            AuditContextHolder auditContextHolder) {
        this.auditLogWriter = auditLogWriter;
        this.objectMapper = objectMapper;
        this.auditContextHolder = auditContextHolder;
    }

    @Override
    public void onPostInsert(PostInsertEvent event) {
        EntityPersister persister = event.getPersister();
        String tableName = resolveTableName(event.getEntity(), persister);
        if (shouldSkip(tableName)) {
            return;
        }

        Map<String, Object> afterState = extractState(
            persister.getPropertyNames(),
            event.getState(),
            persister,
            event.getId(),
            event.getSession());

        writeAuditLog(tableName, "INSERT", event.getId(), null, afterState);
    }

    @Override
    public void onPostUpdate(PostUpdateEvent event) {
        EntityPersister persister = event.getPersister();
        String tableName = resolveTableName(event.getEntity(), persister);
        if (shouldSkip(tableName)) {
            return;
        }

        Map<String, Object> beforeState = extractState(
            persister.getPropertyNames(),
            event.getOldState(),
            persister,
            event.getId(),
            event.getSession());

        Map<String, Object> afterState = extractState(
            persister.getPropertyNames(),
            event.getState(),
            persister,
            event.getId(),
            event.getSession());

        writeAuditLog(tableName, "UPDATE", event.getId(), beforeState, afterState);
    }

    @Override
    public void onPostDelete(PostDeleteEvent event) {
        EntityPersister persister = event.getPersister();
        String tableName = resolveTableName(event.getEntity(), persister);
        if (shouldSkip(tableName)) {
            return;
        }

        Map<String, Object> beforeState = extractState(
            persister.getPropertyNames(),
            event.getDeletedState(),
            persister,
            event.getId(),
            event.getSession());

        writeAuditLog(tableName, "DELETE", event.getId(), beforeState, null);
    }

    private void writeAuditLog(
            String tableName,
            String operation,
            Object entityId,
            Map<String, Object> beforeState,
            Map<String, Object> afterState) {
        auditLogWriter.write(
            tableName,
            operation,
            entityId == null ? null : String.valueOf(entityId),
            resolveActor(),
            toJson(beforeState),
            toJson(afterState),
            auditContextHolder.getOrCreateRequestId());
    }

    private Map<String, Object> extractState(
            String[] propertyNames,
            Object[] state,
            EntityPersister persister,
            Object entityId,
            SharedSessionContractImplementor session) {
        Map<String, Object> payload = new LinkedHashMap<>();
        String idPropertyName = persister.getIdentifierPropertyName();

        if (idPropertyName != null && !idPropertyName.isBlank()) {
            payload.put(idPropertyName, sanitizeValue(entityId, session));
        } else {
            payload.put("id", sanitizeValue(entityId, session));
        }

        if (propertyNames == null || state == null) {
            return payload;
        }

        int length = Math.min(propertyNames.length, state.length);
        for (int i = 0; i < length; i++) {
            payload.put(propertyNames[i], sanitizeValue(state[i], session));
        }

        return payload;
    }

    private Object sanitizeValue(Object value, SharedSessionContractImplementor session) {
        if (value == null) {
            return null;
        }

        if (value instanceof String stringValue) {
            return stringValue;
        }

        if (value instanceof Number || value instanceof Boolean || value instanceof Character || value instanceof Enum<?>) {
            return value;
        }

        if (value instanceof Temporal temporalValue) {
            return temporalValue.toString();
        }

        if (value instanceof Collection<?> collectionValue) {
            return "COLLECTION(size=" + collectionValue.size() + ")";
        }

        if (value instanceof HibernateProxy proxy) {
            return proxy.getHibernateLazyInitializer().getIdentifier();
        }

        if (session != null && value != null) {
            Object identifier = session.getContextEntityIdentifier(value);
            if (identifier != null) {
                return identifier;
            }
        }

        Object reflectedId = tryExtractId(value);
        if (reflectedId != null) {
            return reflectedId;
        }

        if (Hibernate.isInitialized(value)) {
            return String.valueOf(value);
        }

        return value.getClass().getSimpleName();
    }

    private Object tryExtractId(Object value) {
        try {
            Method method = value.getClass().getMethod("getId");
            return method.invoke(value);
        } catch (Exception ignored) {
            return null;
        }
    }

    private String resolveActor() {
        String actorFromContext = auditContextHolder.getActor();
        if (actorFromContext != null && !actorFromContext.isBlank()) {
            return actorFromContext;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return "SYSTEM";
        }

        Object principal = authentication.getPrincipal();
        if (principal instanceof JwtPrincipal jwtPrincipal) {
            return jwtPrincipal.username();
        }

        String principalName = authentication.getName();
        if (principalName != null && !principalName.isBlank()) {
            return principalName;
        }

        return "SYSTEM";
    }

    private String toJson(Map<String, Object> payload) {
        if (payload == null) {
            return null;
        }

        Map<String, Object> sanitized = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : payload.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            sanitized.put(key, isSensitiveField(key) ? "***" : value);
        }

        try {
            return objectMapper.writeValueAsString(sanitized);
        } catch (JsonProcessingException ex) {
            return "{\"serialization_error\":\"" + ex.getMessage() + "\"}";
        }
    }

    private boolean isSensitiveField(String fieldName) {
        if (fieldName == null) {
            return false;
        }

        String normalized = fieldName.toLowerCase(Locale.ROOT);
        return normalized.contains("password")
            || normalized.contains("token")
            || normalized.contains("secret");
    }

    private boolean shouldSkip(String tableName) {
        return AUDIT_TABLE_NAME.equalsIgnoreCase(tableName);
    }

    private String resolveTableName(Object entity, EntityPersister persister) {
        if (entity != null) {
            Class<?> entityClass = Hibernate.getClass(entity);
            Table table = entityClass.getAnnotation(Table.class);
            if (table != null && table.name() != null && !table.name().isBlank()) {
                return table.name();
            }
            return entityClass.getSimpleName();
        }

        return normalizeTableName(persister == null ? null : persister.getEntityName());
    }

    private String normalizeTableName(String rawTableName) {
        if (rawTableName == null) {
            return "unknown_table";
        }
        int dotIndex = rawTableName.lastIndexOf('.');
        if (dotIndex >= 0 && dotIndex < rawTableName.length() - 1) {
            return rawTableName.substring(dotIndex + 1);
        }
        return rawTableName;
    }

    @Override
    public boolean requiresPostCommitHandling(EntityPersister persister) {
        return false;
    }
}

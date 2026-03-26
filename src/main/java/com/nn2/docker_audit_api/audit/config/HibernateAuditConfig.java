package com.nn2.docker_audit_api.audit.config;

import java.util.List;

import org.hibernate.boot.Metadata;
import org.hibernate.boot.spi.BootstrapContext;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.event.service.spi.EventListenerRegistry;
import org.hibernate.event.spi.EventType;
import org.hibernate.integrator.spi.Integrator;
import org.hibernate.jpa.boot.spi.IntegratorProvider;
import org.hibernate.service.spi.SessionFactoryServiceRegistry;
import org.springframework.boot.autoconfigure.orm.jpa.HibernatePropertiesCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.nn2.docker_audit_api.audit.service.HibernateAuditEventListener;

@Configuration
public class HibernateAuditConfig {

    @Bean
    HibernatePropertiesCustomizer hibernateAuditCustomizer(HibernateAuditEventListener listener) {
        return properties -> properties.put(
            "hibernate.integrator_provider",
            (IntegratorProvider) () -> List.of(new AuditIntegrator(listener)));
    }

    private static class AuditIntegrator implements Integrator {

        private final HibernateAuditEventListener listener;

        private AuditIntegrator(HibernateAuditEventListener listener) {
            this.listener = listener;
        }

        @Override
        public void integrate(
                Metadata metadata,
                BootstrapContext bootstrapContext,
                SessionFactoryImplementor sessionFactory) {
            EventListenerRegistry registry = sessionFactory
                .getServiceRegistry()
                .getService(EventListenerRegistry.class);

            registry.getEventListenerGroup(EventType.POST_INSERT).appendListener(listener);
            registry.getEventListenerGroup(EventType.POST_UPDATE).appendListener(listener);
            registry.getEventListenerGroup(EventType.POST_DELETE).appendListener(listener);
        }

        @Override
        public void disintegrate(
                SessionFactoryImplementor sessionFactory,
                SessionFactoryServiceRegistry serviceRegistry) {
            // no-op
        }
    }
}

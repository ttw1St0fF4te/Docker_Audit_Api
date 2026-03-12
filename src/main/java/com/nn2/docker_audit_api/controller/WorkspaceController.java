package com.nn2.docker_audit_api.controller;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nn2.docker_audit_api.auth.dto.WorkspaceResponse;

@RestController
@RequestMapping("/api/pages")
public class WorkspaceController {

	@GetMapping("/security-engineer")
	public WorkspaceResponse securityEngineerPage() {
		return new WorkspaceResponse(
			"SECURITY_ENGINEER",
			"Рабочее пространство инженера безопасности",
			"Здесь позже появятся настройки CIS, расписания сканирований, уведомления и аналитические дашборды.",
			List.of(
				"Включение и выключение CIS-конфигураций для профилей проверки.",
				"Ручной запуск сканирования и настройка расписания по docker-hostам.",
				"Настройка каналов уведомлений и шаблонов реакции на уязвимости.",
				"Просмотр истории сканирований и генерация отчетов для аудита."),
			List.of(
				"Добавить CRUD для профилей CIS и расписаний.",
				"Подключить ClickHouse как источник трендов и агрегированной аналитики.",
				"Реализовать дашборд по динамике критичных находок."));
	}

	@GetMapping("/developer")
	public WorkspaceResponse developerPage() {
		return new WorkspaceResponse(
			"DEVELOPER",
			"Рабочее пространство разработчика",
			"Здесь позже будет список контейнеров, найденных уязвимостей и подтверждение исправлений.",
			List.of(
				"Просмотр контейнеров и назначенных разработчику уязвимостей.",
				"Получение рекомендаций по исправлению и контекстных инструкций.",
				"Подтверждение или отклонение факта исправления найденной проблемы."),
			List.of(
				"Сделать список контейнеров и карточку уязвимости.",
				"Добавить статус подтверждения исправления.",
				"Подготовить ленту уведомлений по новым находкам."));
	}

	@GetMapping("/super-admin")
	public WorkspaceResponse superAdminPage() {
		return new WorkspaceResponse(
			"SUPER_ADMIN",
			"Рабочее пространство супер-администратора",
			"Здесь позже будут управление пользователями, аудит действий и подключенные docker-hostы.",
			List.of(
				"Создание, блокировка, восстановление и редактирование пользователей.",
				"Просмотр журналов действий пользователей и системных событий.",
				"Подключение и удаление docker-hostов для сканирования."),
			List.of(
				"Спроектировать CRUD пользователей и восстановление доступа.",
				"Добавить журнал аудита действий в PostgreSQL и ClickHouse.",
				"Подготовить реестр docker-hostов и проверку доступности."));
	}
}
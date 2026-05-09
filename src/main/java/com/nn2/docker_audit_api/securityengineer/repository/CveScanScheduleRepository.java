package com.nn2.docker_audit_api.securityengineer.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.nn2.docker_audit_api.securityengineer.entity.CveScanScheduleEntity;

public interface CveScanScheduleRepository extends JpaRepository<CveScanScheduleEntity, Long> {

    List<CveScanScheduleEntity> findByActiveTrueOrderByIdAsc();

    Optional<CveScanScheduleEntity> findFirstByHostIdOrderByIdDesc(Long hostId);

    List<CveScanScheduleEntity> findByHostIdOrderByIdAsc(Long hostId);

    boolean existsByHostIdAndActiveTrue(Long hostId);

    void deleteByHostId(Long hostId);
}

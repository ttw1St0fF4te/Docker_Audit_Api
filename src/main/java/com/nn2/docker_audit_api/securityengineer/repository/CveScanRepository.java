package com.nn2.docker_audit_api.securityengineer.repository;

import java.util.List;
import java.util.Optional;
import java.time.Instant;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.nn2.docker_audit_api.securityengineer.entity.CveScanEntity;

public interface CveScanRepository extends JpaRepository<CveScanEntity, Long>, JpaSpecificationExecutor<CveScanEntity> {

    List<CveScanEntity> findTop20ByOrderByStartedAtDesc();

    boolean existsByHostIdAndStatus(Long hostId, String status);

    Optional<CveScanEntity> findTopByHostIdAndStatusOrderByStartedAtDesc(Long hostId, String status);

        @Query("""
            SELECT s.id
            FROM CveScanEntity s
            WHERE s.status = 'COMPLETED'
            AND s.startedAt >= :from
            AND s.startedAt < :to
            AND (:hostId IS NULL OR s.hostId = :hostId)
            """)
        List<Long> findCompletedScanIdsByRange(
            @Param("from") Instant from,
            @Param("to") Instant to,
            @Param("hostId") Long hostId);

            @Query("""
                SELECT s
                FROM CveScanEntity s
                WHERE s.status = 'COMPLETED'
                AND s.startedAt >= :from
                AND s.startedAt < :to
                AND (:hostId IS NULL OR s.hostId = :hostId)
                """)
            List<CveScanEntity> findCompletedScansByRange(
                @Param("from") Instant from,
                @Param("to") Instant to,
                @Param("hostId") Long hostId);

        @Query("""
            SELECT COUNT(s)
            FROM CveScanEntity s
            WHERE s.startedAt >= :from
            AND s.startedAt < :to
            AND (:hostId IS NULL OR s.hostId = :hostId)
            """)
        long countAllByRange(
            @Param("from") Instant from,
            @Param("to") Instant to,
            @Param("hostId") Long hostId);
}

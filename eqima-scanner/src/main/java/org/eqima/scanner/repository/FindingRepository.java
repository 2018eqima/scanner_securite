package org.eqima.scanner.repository;

import org.eqima.scanner.entity.Finding;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FindingRepository extends JpaRepository<Finding, String> {

    List<Finding> findBySessionIdOrderBySeverityAscDetectedAtAsc(String sessionId);

    long countBySessionIdAndSeverity(String sessionId, Finding.Severity severity);
}
package org.eqima.scanner.repository;

import org.eqima.scanner.entity.AttackFinding;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface AttackFindingRepository extends JpaRepository<AttackFinding, String> {
    List<AttackFinding> findByJobIdOrderBySeverityAscTitleAsc(String jobId);
    long countByJobId(String jobId);
}
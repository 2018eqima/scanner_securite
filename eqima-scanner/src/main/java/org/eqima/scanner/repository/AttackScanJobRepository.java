package org.eqima.scanner.repository;

import org.eqima.scanner.entity.AttackScanJob;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface AttackScanJobRepository extends JpaRepository<AttackScanJob, String> {
    List<AttackScanJob> findAllByOrderByStartedAtDesc();
}
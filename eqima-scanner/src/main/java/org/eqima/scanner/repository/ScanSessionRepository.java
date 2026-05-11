package org.eqima.scanner.repository;

import org.eqima.scanner.entity.ScanSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScanSessionRepository extends JpaRepository<ScanSession, String> {

    List<ScanSession> findAllByOrderByStartedAtDesc();

    List<ScanSession> findByTargetIdOrderByStartedAtDesc(String targetId);
}
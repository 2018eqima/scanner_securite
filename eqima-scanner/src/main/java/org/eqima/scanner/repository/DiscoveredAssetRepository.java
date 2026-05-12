package org.eqima.scanner.repository;

import org.eqima.scanner.entity.DiscoveredAsset;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface DiscoveredAssetRepository extends JpaRepository<DiscoveredAsset, String> {
    List<DiscoveredAsset> findByJobIdOrderByRiskScoreDesc(String jobId);
    long countByJobId(String jobId);
}
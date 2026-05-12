package org.eqima.scanner.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "attack_scan_jobs")
public class AttackScanJob {

    public enum Status { PENDING, RUNNING, DONE, FAILED }

    @Id
    private String id;

    @Column(nullable = false)
    private String domain;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Status status = Status.PENDING;

    @Column(columnDefinition = "TEXT")
    private String currentPhase;

    private int progress = 0;
    private int assetCount = 0;
    private int findingCount = 0;
    private int riskScore = 0;

    private Instant startedAt;
    private Instant completedAt;

    @Column(columnDefinition = "TEXT")
    private String error;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getDomain() { return domain; }
    public void setDomain(String domain) { this.domain = domain; }
    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
    public String getCurrentPhase() { return currentPhase; }
    public void setCurrentPhase(String currentPhase) { this.currentPhase = currentPhase; }
    public int getProgress() { return progress; }
    public void setProgress(int progress) { this.progress = progress; }
    public int getAssetCount() { return assetCount; }
    public void setAssetCount(int assetCount) { this.assetCount = assetCount; }
    public int getFindingCount() { return findingCount; }
    public void setFindingCount(int findingCount) { this.findingCount = findingCount; }
    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    public Instant getStartedAt() { return startedAt; }
    public void setStartedAt(Instant startedAt) { this.startedAt = startedAt; }
    public Instant getCompletedAt() { return completedAt; }
    public void setCompletedAt(Instant completedAt) { this.completedAt = completedAt; }
    public String getError() { return error; }
    public void setError(String error) { this.error = error; }
}
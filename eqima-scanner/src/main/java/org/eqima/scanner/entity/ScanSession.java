package org.eqima.scanner.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "scan_sessions")
public class ScanSession {

    public enum Status { PENDING, RUNNING, COMPLETED, FAILED }

    @Id
    private String id;

    @Column(nullable = false)
    private String targetId;

    @Column(nullable = false)
    private String targetName;

    @Column(nullable = false)
    private String targetUrl;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Status status = Status.PENDING;

    private Instant startedAt;
    private Instant completedAt;

    private String zapScanId;
    private String zapSpiderId;

    private Integer progress = 0;
    private Integer totalFindings = 0;

    @Column(length = 8)
    private String sslGrade;

    @Column(columnDefinition = "TEXT")
    private String sslData; // JSON complet SSL Labs

    @Column(columnDefinition = "TEXT")
    private String techData; // JSON stack technique détecté

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getTargetId() { return targetId; }
    public void setTargetId(String targetId) { this.targetId = targetId; }

    public String getTargetName() { return targetName; }
    public void setTargetName(String targetName) { this.targetName = targetName; }

    public String getTargetUrl() { return targetUrl; }
    public void setTargetUrl(String targetUrl) { this.targetUrl = targetUrl; }

    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }

    public Instant getStartedAt() { return startedAt; }
    public void setStartedAt(Instant startedAt) { this.startedAt = startedAt; }

    public Instant getCompletedAt() { return completedAt; }
    public void setCompletedAt(Instant completedAt) { this.completedAt = completedAt; }

    public String getZapScanId() { return zapScanId; }
    public void setZapScanId(String zapScanId) { this.zapScanId = zapScanId; }

    public String getZapSpiderId() { return zapSpiderId; }
    public void setZapSpiderId(String zapSpiderId) { this.zapSpiderId = zapSpiderId; }

    public Integer getProgress() { return progress; }
    public void setProgress(Integer progress) { this.progress = progress; }

    public Integer getTotalFindings() { return totalFindings; }
    public void setTotalFindings(Integer totalFindings) { this.totalFindings = totalFindings; }

    public String getSslGrade() { return sslGrade; }
    public void setSslGrade(String sslGrade) { this.sslGrade = sslGrade; }

    public String getSslData() { return sslData; }
    public void setSslData(String sslData) { this.sslData = sslData; }

    public String getTechData() { return techData; }
    public void setTechData(String techData) { this.techData = techData; }
}
package org.eqima.scanner.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "attack_findings")
public class AttackFinding {

    /** SENSITIVE_FILE | MISSING_HEADER | WEAK_TLS | DNS_ISSUE | EXPOSED_TECH | WAYBACK_URL | ASN_INFO */
    @Id
    private String id;

    @Column(nullable = false)
    private String jobId;

    private String assetValue;

    @Column(nullable = false)
    private String category;

    @Column(nullable = false)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String description;

    /** CRITICAL | HIGH | MEDIUM | LOW | INFO */
    @Column(nullable = false)
    private String severity;

    @Column(columnDefinition = "TEXT")
    private String evidence;

    @Column(columnDefinition = "TEXT")
    private String remediation;

    private Instant discoveredAt = Instant.now();

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getJobId() { return jobId; }
    public void setJobId(String jobId) { this.jobId = jobId; }
    public String getAssetValue() { return assetValue; }
    public void setAssetValue(String assetValue) { this.assetValue = assetValue; }
    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    public String getEvidence() { return evidence; }
    public void setEvidence(String evidence) { this.evidence = evidence; }
    public String getRemediation() { return remediation; }
    public void setRemediation(String remediation) { this.remediation = remediation; }
    public Instant getDiscoveredAt() { return discoveredAt; }
    public void setDiscoveredAt(Instant discoveredAt) { this.discoveredAt = discoveredAt; }
}
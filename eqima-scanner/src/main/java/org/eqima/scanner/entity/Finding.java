package org.eqima.scanner.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "findings")
public class Finding {

    // Ordre important : HIGH=0 pour ORDER BY severity ASC → critiques en premier
    public enum Severity { HIGH, MEDIUM, LOW, INFORMATIONAL }

    @Id
    private String id;

    @Column(nullable = false)
    private String sessionId;

    @Column(length = 2048)
    private String url;

    @Column(nullable = false)
    private String name;

    @Column(length = 4096)
    private String description;

    @Column(length = 4096)
    private String solution;

    @Column(length = 1024)
    private String reference;

    @Enumerated(EnumType.ORDINAL)
    @Column(nullable = false)
    private Severity severity;

    @Column(length = 2048)
    private String evidence;

    private String cweid;
    private String wascid;

    private Instant detectedAt;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getSolution() { return solution; }
    public void setSolution(String solution) { this.solution = solution; }

    public String getReference() { return reference; }
    public void setReference(String reference) { this.reference = reference; }

    public Severity getSeverity() { return severity; }
    public void setSeverity(Severity severity) { this.severity = severity; }

    public String getEvidence() { return evidence; }
    public void setEvidence(String evidence) { this.evidence = evidence; }

    public String getCweid() { return cweid; }
    public void setCweid(String cweid) { this.cweid = cweid; }

    public String getWascid() { return wascid; }
    public void setWascid(String wascid) { this.wascid = wascid; }

    public Instant getDetectedAt() { return detectedAt; }
    public void setDetectedAt(Instant detectedAt) { this.detectedAt = detectedAt; }
}
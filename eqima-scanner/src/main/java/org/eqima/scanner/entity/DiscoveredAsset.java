package org.eqima.scanner.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "discovered_assets")
public class DiscoveredAsset {

    /** SUBDOMAIN | IP | ENDPOINT | SENSITIVE_PATH */
    @Id
    private String id;

    @Column(nullable = false)
    private String jobId;

    @Column(nullable = false)
    private String type;

    @Column(nullable = false, length = 512)
    private String value;

    private String ip;
    private String asn;
    private String country;
    private String org;
    private boolean active = true;
    private int riskScore = 0;

    /** JSON: open ports, TLS version, headers summary … */
    @Column(columnDefinition = "TEXT")
    private String metadata;

    private Instant discoveredAt = Instant.now();

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getJobId() { return jobId; }
    public void setJobId(String jobId) { this.jobId = jobId; }
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public String getValue() { return value; }
    public void setValue(String value) { this.value = value; }
    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }
    public String getAsn() { return asn; }
    public void setAsn(String asn) { this.asn = asn; }
    public String getCountry() { return country; }
    public void setCountry(String country) { this.country = country; }
    public String getOrg() { return org; }
    public void setOrg(String org) { this.org = org; }
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    public String getMetadata() { return metadata; }
    public void setMetadata(String metadata) { this.metadata = metadata; }
    public Instant getDiscoveredAt() { return discoveredAt; }
    public void setDiscoveredAt(Instant discoveredAt) { this.discoveredAt = discoveredAt; }
}
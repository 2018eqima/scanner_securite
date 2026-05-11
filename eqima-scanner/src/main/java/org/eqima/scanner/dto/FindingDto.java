package org.eqima.scanner.dto;

import org.eqima.scanner.entity.Finding;

import java.time.Instant;

public record FindingDto(
        String id,
        String sessionId,
        String url,
        String name,
        String description,
        String solution,
        Finding.Severity severity,
        String evidence,
        String cweid,
        String wascid,
        Instant detectedAt
) {
    public static FindingDto from(Finding f) {
        return new FindingDto(
                f.getId(),
                f.getSessionId(),
                f.getUrl(),
                f.getName(),
                f.getDescription(),
                f.getSolution(),
                f.getSeverity(),
                f.getEvidence(),
                f.getCweid(),
                f.getWascid(),
                f.getDetectedAt()
        );
    }
}
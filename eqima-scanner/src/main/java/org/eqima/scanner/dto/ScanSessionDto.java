package org.eqima.scanner.dto;

import org.eqima.scanner.entity.ScanSession;

import java.time.Instant;

public record ScanSessionDto(
        String id,
        String targetId,
        String targetName,
        String targetUrl,
        ScanSession.Status status,
        Instant startedAt,
        Instant completedAt,
        Integer progress,
        Integer totalFindings
) {
    public static ScanSessionDto from(ScanSession s) {
        return new ScanSessionDto(
                s.getId(),
                s.getTargetId(),
                s.getTargetName(),
                s.getTargetUrl(),
                s.getStatus(),
                s.getStartedAt(),
                s.getCompletedAt(),
                s.getProgress(),
                s.getTotalFindings()
        );
    }
}
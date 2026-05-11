package org.eqima.scanner.dto;

public record ScanEvent(
        String sessionId,
        String type,       // STARTED | SPIDER_PROGRESS | SCAN_PROGRESS | FINDING | COMPLETED | ERROR
        String message,
        Integer progress,  // 0–100
        Object data        // FindingDto ou null
) {}
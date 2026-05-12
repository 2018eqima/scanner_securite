package org.eqima.scanner.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;

@Service
public class TlsAnalysisService {

    private static final Logger log = LoggerFactory.getLogger(TlsAnalysisService.class);

    public record TlsResult(
        String host,
        boolean reachable,
        String protocol,       // TLSv1.3, TLSv1.2, TLSv1.1, TLSv1.0
        String cipherSuite,
        boolean certValid,
        boolean certExpired,
        String certExpiry,
        String certSubject,
        List<String> sans,
        boolean hstsPresent,
        boolean weakProtocol,  // true if TLS < 1.2
        String error
    ) {}

    public TlsResult analyze(String host) {
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            try (SSLSocket socket = (SSLSocket) factory.createSocket(host, 443)) {
                socket.setSoTimeout(8000);

                // Force handshake
                socket.startHandshake();
                SSLSession session = socket.getSession();

                String protocol    = session.getProtocol();
                String cipher      = session.getCipherSuite();
                boolean weak       = protocol.equals("TLSv1") || protocol.equals("TLSv1.1") || protocol.equals("SSLv3");

                // Certificate details
                java.security.cert.Certificate[] certs = session.getPeerCertificates();
                String subject = "unknown";
                boolean expired = false;
                String expiry = null;
                List<String> sans = new ArrayList<>();

                if (certs.length > 0 && certs[0] instanceof X509Certificate x509) {
                    subject = x509.getSubjectX500Principal().getName();
                    expiry  = x509.getNotAfter().toInstant().toString();
                    expired = x509.getNotAfter().toInstant().isBefore(Instant.now());

                    // Extract SANs
                    try {
                        Collection<List<?>> altNames = x509.getSubjectAlternativeNames();
                        if (altNames != null) {
                            for (List<?> altName : altNames) {
                                if (altName.size() >= 2 && altName.get(0) instanceof Integer type) {
                                    if (type == 2) sans.add(altName.get(1).toString()); // DNS SAN
                                }
                            }
                        }
                    } catch (Exception ignored) {}
                }

                log.info("TLS {} {} cipher={} expired={} SANs={}", host, protocol, cipher, expired, sans.size());
                return new TlsResult(host, true, protocol, cipher, !expired, expired, expiry, subject, sans, false, weak, null);
            }
        } catch (Exception e) {
            log.debug("TLS analysis failed for {}: {}", host, e.getMessage());
            return new TlsResult(host, false, null, null, false, false, null, null, List.of(), false, false, e.getMessage());
        }
    }
}
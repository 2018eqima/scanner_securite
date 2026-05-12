package org.eqima.scanner.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.eqima.scanner.entity.AttackFinding;
import org.eqima.scanner.entity.AttackScanJob;
import org.eqima.scanner.entity.DiscoveredAsset;
import org.eqima.scanner.repository.AttackFindingRepository;
import org.eqima.scanner.repository.AttackScanJobRepository;
import org.eqima.scanner.repository.DiscoveredAssetRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;
import reactor.core.scheduler.Schedulers;

import java.net.InetAddress;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

@Service
public class AttackSurfaceOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(AttackSurfaceOrchestrator.class);

    private final AttackScanJobRepository       jobRepo;
    private final DiscoveredAssetRepository     assetRepo;
    private final AttackFindingRepository       findingRepo;
    private final SubdomainDiscoveryService     subdomainSvc;
    private final DnsReconService               dnsSvc;
    private final AsnService                    asnSvc;
    private final WaybackService                waybackSvc;
    private final HttpFingerprintService        httpSvc;
    private final TlsAnalysisService            tlsSvc;
    private final ObjectMapper                  mapper;

    // Per-job SSE sinks
    private final ConcurrentHashMap<String, Sinks.Many<ServerSentEvent<String>>> sinks = new ConcurrentHashMap<>();

    public AttackSurfaceOrchestrator(
        AttackScanJobRepository jobRepo,
        DiscoveredAssetRepository assetRepo,
        AttackFindingRepository findingRepo,
        SubdomainDiscoveryService subdomainSvc,
        DnsReconService dnsSvc,
        AsnService asnSvc,
        WaybackService waybackSvc,
        HttpFingerprintService httpSvc,
        TlsAnalysisService tlsSvc,
        ObjectMapper mapper
    ) {
        this.jobRepo      = jobRepo;
        this.assetRepo    = assetRepo;
        this.findingRepo  = findingRepo;
        this.subdomainSvc = subdomainSvc;
        this.dnsSvc       = dnsSvc;
        this.asnSvc       = asnSvc;
        this.waybackSvc   = waybackSvc;
        this.httpSvc      = httpSvc;
        this.tlsSvc       = tlsSvc;
        this.mapper       = mapper;
    }

    /** Start a new scan and return the job ID immediately */
    public String startScan(String domain) {
        String id = UUID.randomUUID().toString();
        AttackScanJob job = new AttackScanJob();
        job.setId(id);
        job.setDomain(domain.toLowerCase().replaceAll("https?://", "").replaceAll("/.*", ""));
        job.setStatus(AttackScanJob.Status.PENDING);
        job.setStartedAt(Instant.now());
        jobRepo.save(job);

        Sinks.Many<ServerSentEvent<String>> sink = Sinks.many().multicast().onBackpressureBuffer(256, false);
        sinks.put(id, sink);

        // Run asynchronously
        Schedulers.boundedElastic().schedule(() -> runScan(id));

        return id;
    }

    public Flux<ServerSentEvent<String>> stream(String jobId) {
        Sinks.Many<ServerSentEvent<String>> sink = sinks.get(jobId);
        if (sink == null) {
            return Flux.just(ServerSentEvent.<String>builder().event("error").data("Job not found: " + jobId).build());
        }
        return sink.asFlux();
    }

    // ─── Main scan pipeline ─────────────────────────────────────────────────

    private void runScan(String jobId) {
        try {
            AttackScanJob job = jobRepo.findById(jobId).orElseThrow();
            String domain = job.getDomain();

            update(job, AttackScanJob.Status.RUNNING, "Démarrage…", 0);

            // ── PHASE 1 : Passive recon (parallel) ──────────────────────────
            emit(jobId, "phase", "PHASE 1 — Reconnaissance passive");

            // Launch all Phase 1 tasks in parallel
            CompletableFuture<List<Map<String, Object>>> crtFuture =
                CompletableFuture.supplyAsync(() -> {
                    emit(jobId, "step", "crt.sh — Certificate Transparency…");
                    return subdomainSvc.discover(domain).block();
                });

            CompletableFuture<DnsReconService.DnsResult> dnsFuture =
                CompletableFuture.supplyAsync(() -> {
                    emit(jobId, "step", "DNS — résolution A/MX/NS/TXT/SPF/DKIM/DMARC…");
                    return dnsSvc.recon(domain);
                });

            CompletableFuture<AsnService.AsnResult> asnFuture =
                CompletableFuture.supplyAsync(() -> {
                    emit(jobId, "step", "ASN — lookup BGPView…");
                    return asnSvc.lookupDomain(domain);
                });

            CompletableFuture<WaybackService.WaybackResult> waybackFuture =
                CompletableFuture.supplyAsync(() -> {
                    emit(jobId, "step", "Wayback Machine — URLs historiques…");
                    return waybackSvc.fetch(domain);
                });

            // Wait for all Phase 1
            CompletableFuture.allOf(crtFuture, dnsFuture, asnFuture, waybackFuture).get(90, TimeUnit.SECONDS);

            List<Map<String, Object>> crtSubdomains = crtFuture.get();
            DnsReconService.DnsResult dnsResult     = dnsFuture.get();
            AsnService.AsnResult asnResult          = asnFuture.get();
            WaybackService.WaybackResult wayback    = waybackFuture.get();

            update(job, AttackScanJob.Status.RUNNING, "Phase 1 terminée — analyse…", 25);

            // ── Persist Phase 1 assets ──────────────────────────────────────
            Set<String> allSubdomains = new LinkedHashSet<>();

            // From crt.sh
            if (crtSubdomains != null) {
                crtSubdomains.stream()
                    .filter(s -> Boolean.TRUE.equals(s.get("active")))
                    .forEach(s -> allSubdomains.add((String) s.get("subdomain")));
            }
            // From DNS brute-force
            allSubdomains.addAll(dnsResult.subdomainsFromBruteForce());

            // Save subdomains as assets
            for (Map<String, Object> sub : (crtSubdomains != null ? crtSubdomains : List.<Map<String,Object>>of())) {
                saveAsset(jobId, "SUBDOMAIN", (String) sub.get("subdomain"),
                    (String) sub.get("ip"), null, (String) sub.get("country"), (String) sub.get("org"),
                    Boolean.TRUE.equals(sub.get("active")));
            }

            // DNS findings
            persistDnsFindings(jobId, domain, dnsResult);

            // ASN info
            if (asnResult.asn() != null) {
                emit(jobId, "step", "ASN " + asnResult.asn() + " (" + asnResult.asnName() + ") — " + asnResult.prefixes().size() + " préfixes IP");
                saveAsset(jobId, "IP", domain, null, asnResult.asn(), asnResult.countryCode(), asnResult.asnName(), true);
                for (String prefix : asnResult.prefixes()) {
                    saveAsset(jobId, "IP", prefix, null, asnResult.asn(), asnResult.countryCode(), asnResult.asnName(), true);
                }
            }

            // Wayback URLs
            int waybackCount = wayback.urls().size();
            if (waybackCount > 0) {
                emit(jobId, "step", "Wayback — " + waybackCount + " URLs historiques trouvées");
                // Save as findings (interesting old endpoints)
                for (WaybackService.WaybackUrl url : wayback.urls().stream().limit(50).collect(Collectors.toList())) {
                    saveFinding(jobId, url.url(), "WAYBACK_URL",
                        "Endpoint historique : " + url.url(),
                        "URL active sur Wayback Machine (timestamp " + url.timestamp() + "). Peut exposer des endpoints dépréciés ou des données sensibles.",
                        "INFO",
                        "HTTP " + url.statusCode() + " — " + url.mimeType(),
                        "Vérifier que cet endpoint est toujours nécessaire et sécurisé.");
                }
            }

            // ── PHASE 2 : Active recon ──────────────────────────────────────
            emit(jobId, "phase", "PHASE 2 — Reconnaissance active");
            update(job, AttackScanJob.Status.RUNNING, "Phase 2 — Fingerprinting HTTP & TLS…", 35);

            // For each active subdomain: HTTP fingerprint + TLS
            List<String> activeHosts = allSubdomains.stream()
                .filter(s -> {
                    try { InetAddress.getByName(s); return true; }
                    catch (Exception e) { return false; }
                })
                .limit(30) // cap to avoid timeout
                .collect(Collectors.toList());

            emit(jobId, "step", "Fingerprinting " + activeHosts.size() + " hôtes actifs…");

            int done = 0;
            for (String host : activeHosts) {
                emit(jobId, "step", "→ " + host);

                // TLS analysis
                TlsAnalysisService.TlsResult tls = tlsSvc.analyze(host);
                persistTlsFindings(jobId, host, tls);

                // HTTP fingerprint + sensitive files
                String url = tls.reachable() ? "https://" + host : "http://" + host;
                HttpFingerprintService.FingerprintResult fp = httpSvc.fingerprint(url);
                persistHttpFindings(jobId, host, url, fp);

                done++;
                int prog = 35 + (int) (done * 40.0 / Math.max(activeHosts.size(), 1));
                update(job, AttackScanJob.Status.RUNNING, "Phase 2 — " + host, prog);
            }

            // ── PHASE 3 : Scoring ───────────────────────────────────────────
            emit(jobId, "phase", "PHASE 3 — Scoring & corrélation");
            update(job, AttackScanJob.Status.RUNNING, "Calcul du score de risque…", 80);

            long findings   = findingRepo.countByJobId(jobId);
            long assets     = assetRepo.countByJobId(jobId);
            int score       = computeScore(jobId);

            job.setAssetCount((int) assets);
            job.setFindingCount((int) findings);
            job.setRiskScore(score);
            job.setStatus(AttackScanJob.Status.DONE);
            job.setCurrentPhase("Terminé");
            job.setProgress(100);
            job.setCompletedAt(Instant.now());
            jobRepo.save(job);

            emit(jobId, "done", mapper.createObjectNode()
                .put("assets", assets)
                .put("findings", findings)
                .put("score", score)
                .toString());

        } catch (Exception e) {
            log.error("Attack surface scan failed for job {}: {}", jobId, e.getMessage(), e);
            jobRepo.findById(jobId).ifPresent(job -> {
                job.setStatus(AttackScanJob.Status.FAILED);
                job.setError(e.getMessage());
                job.setCompletedAt(Instant.now());
                jobRepo.save(job);
            });
            emit(jobId, "error", e.getMessage());
        } finally {
            Sinks.Many<ServerSentEvent<String>> sink = sinks.get(jobId);
            if (sink != null) sink.tryEmitComplete();
        }
    }

    // ─── Persist helpers ────────────────────────────────────────────────────

    private void persistDnsFindings(String jobId, String domain, DnsReconService.DnsResult dns) {
        if (dns.spf() == null) {
            saveFinding(jobId, domain, "DNS_ISSUE",
                "SPF absent sur " + domain,
                "Aucun enregistrement SPF (Sender Policy Framework) trouvé. Le domaine peut être utilisé pour envoyer des e-mails frauduleux en votre nom.",
                "HIGH",
                "Aucun TXT v=spf1 trouvé",
                "Ajouter un enregistrement TXT SPF : v=spf1 include:_spf.google.com ~all");
        }
        if (dns.dmarc() == null) {
            saveFinding(jobId, domain, "DNS_ISSUE",
                "DMARC absent sur " + domain,
                "Aucun enregistrement DMARC trouvé. Sans DMARC, les e-mails de phishing usurpant votre domaine ne sont pas bloqués.",
                "HIGH",
                "Aucun TXT v=DMARC1 sur _dmarc." + domain,
                "Ajouter : _dmarc." + domain + " TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain + "\"");
        }
        if (dns.dkimSelectors().isEmpty()) {
            saveFinding(jobId, domain, "DNS_ISSUE",
                "DKIM non détecté sur " + domain,
                "Aucun sélecteur DKIM standard trouvé. Sans DKIM, l'authenticité des e-mails n'est pas vérifiable.",
                "MEDIUM",
                "Sélecteurs testés : default, google, mail, dkim, k1, s1, s2, selector1, selector2",
                "Configurer DKIM sur votre serveur mail et publier la clé publique en DNS TXT.");
        }
    }

    private void persistTlsFindings(String jobId, String host, TlsAnalysisService.TlsResult tls) {
        if (!tls.reachable()) {
            saveFinding(jobId, host, "WEAK_TLS",
                "HTTPS non disponible sur " + host,
                "Impossible d'établir une connexion TLS sur le port 443. Le service est peut-être en HTTP pur.",
                "HIGH", tls.error(),
                "Configurer un certificat TLS valide (Let's Encrypt) et rediriger HTTP → HTTPS.");
            return;
        }
        if (tls.weakProtocol()) {
            saveFinding(jobId, host, "WEAK_TLS",
                "Protocole TLS faible : " + tls.protocol() + " sur " + host,
                tls.protocol() + " est vulnérable (POODLE, BEAST, DROWN…). Désactiver immédiatement.",
                "CRITICAL", "Protocole négocié : " + tls.protocol() + " / Cipher : " + tls.cipherSuite(),
                "Désactiver TLS 1.0 et 1.1. Forcer TLS 1.2 minimum, idéalement TLS 1.3.");
        }
        if (tls.certExpired()) {
            saveFinding(jobId, host, "WEAK_TLS",
                "Certificat TLS expiré sur " + host,
                "Le certificat TLS a expiré le " + tls.certExpiry() + ". Les navigateurs afficheront une erreur de sécurité.",
                "CRITICAL", "Expiry: " + tls.certExpiry() + " — Subject: " + tls.certSubject(),
                "Renouveler le certificat immédiatement. Utiliser Let's Encrypt avec auto-renouvellement (certbot renew --cron).");
        }
    }

    private void persistHttpFindings(String jobId, String host, String url, HttpFingerprintService.FingerprintResult fp) {
        HttpFingerprintService.HeaderResult h = fp.headers();

        // Missing security headers
        Map<String, String[]> headerAdvice = Map.ofEntries(
            Map.entry("Content-Security-Policy",    new String[]{"HIGH",   "Absence de CSP. Permet les attaques XSS et injection de contenu.",
                "Ajouter : Content-Security-Policy: default-src 'self'; script-src 'self'"}),
            Map.entry("Strict-Transport-Security",  new String[]{"HIGH",   "HSTS absent. Le navigateur peut accéder au site en HTTP non chiffré.",
                "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"}),
            Map.entry("X-Frame-Options",            new String[]{"MEDIUM", "Clickjacking possible — X-Frame-Options manquant.",
                "Ajouter : X-Frame-Options: DENY (ou SAMEORIGIN)"}),
            Map.entry("X-Content-Type-Options",     new String[]{"MEDIUM", "MIME sniffing possible — X-Content-Type-Options manquant.",
                "Ajouter : X-Content-Type-Options: nosniff"}),
            Map.entry("Referrer-Policy",            new String[]{"LOW",    "Fuite d'URL de référence potentielle.",
                "Ajouter : Referrer-Policy: strict-origin-when-cross-origin"}),
            Map.entry("Permissions-Policy",         new String[]{"LOW",    "Permissions des API navigateur non restreintes.",
                "Ajouter : Permissions-Policy: camera=(), microphone=(), geolocation=()"}),
            Map.entry("X-XSS-Protection",           new String[]{"LOW",    "Filtre XSS du navigateur non activé.",
                "Ajouter : X-XSS-Protection: 1; mode=block (obsolète mais utile sur anciens navigateurs)"})
        );

        for (String missing : h.missingSecHeaders()) {
            String[] advice = headerAdvice.getOrDefault(missing, new String[]{"LOW", "Header de sécurité manquant.", "Ajouter le header " + missing});
            saveFinding(jobId, host, "MISSING_HEADER",
                missing + " absent sur " + host,
                advice[1], advice[0], "Header non présent dans la réponse HTTP de " + url, advice[2]);
        }

        // Technologies exposed
        for (String tech : h.technologies()) {
            saveFinding(jobId, host, "EXPOSED_TECH",
                "Technologie exposée : " + tech + " sur " + host,
                "Le serveur révèle l'utilisation de " + tech + " via ses headers HTTP. Cette information aide les attaquants à cibler des CVEs connues.",
                "LOW",
                "Détecté via headers HTTP : " + h.serverBanner(),
                "Supprimer ou masquer les headers Server, X-Powered-By. Ex Nginx : server_tokens off;");
        }

        // Cookie issues
        for (String issue : h.cookieIssues()) {
            saveFinding(jobId, host, "MISSING_HEADER",
                "Cookie non sécurisé sur " + host,
                issue + " — Un cookie sans ces flags peut être volé via XSS ou CSRF.",
                "MEDIUM", issue,
                "Configurer tous les cookies avec les flags HttpOnly; Secure; SameSite=Strict");
        }

        // HTTP → HTTPS redirect missing
        if (url.startsWith("http://") && !h.redirectsToHttps()) {
            saveFinding(jobId, host, "MISSING_HEADER",
                "Pas de redirection HTTP → HTTPS sur " + host,
                "Le site répond en HTTP sans rediriger vers HTTPS. Les données sont transmises en clair.",
                "HIGH", "HTTP 200 sans Location: https://",
                "Configurer une redirection 301 permanente de HTTP vers HTTPS.");
        }

        // Sensitive files
        for (HttpFingerprintService.SensitiveFile sf : fp.sensitiveFiles()) {
            String sev = "HIGH";
            if (sf.path().contains(".env") || sf.path().contains(".git") || sf.path().contains("actuator/env")) sev = "CRITICAL";
            else if (sf.path().contains("swagger") || sf.path().contains("openapi") || sf.path().contains("graphql")) sev = "MEDIUM";
            else if (sf.path().contains("robots") || sf.path().contains("sitemap") || sf.path().contains("security.txt")) sev = "INFO";

            saveFinding(jobId, host, "SENSITIVE_FILE",
                "Fichier sensible accessible : " + sf.path() + " sur " + host,
                "Le chemin " + sf.path() + " est accessible publiquement (HTTP " + sf.status() + "). Ce fichier peut exposer des secrets, configurations ou informations structurelles.",
                sev,
                "HTTP " + sf.status() + (sf.snippet().isEmpty() ? "" : " — Extrait : " + sf.snippet()),
                "Bloquer l'accès à ce fichier via le serveur web (deny all dans Nginx/Apache) ou le supprimer du document root.");
        }
    }

    private int computeScore(String jobId) {
        List<AttackFinding> findings = findingRepo.findByJobIdOrderBySeverityAscTitleAsc(jobId);
        int score = 0;
        for (AttackFinding f : findings) {
            score += switch (f.getSeverity()) {
                case "CRITICAL" -> 40;
                case "HIGH"     -> 20;
                case "MEDIUM"   -> 8;
                case "LOW"      -> 3;
                default         -> 1;
            };
        }
        return Math.min(score, 1000);
    }

    // ─── Utility ────────────────────────────────────────────────────────────

    private void update(AttackScanJob job, AttackScanJob.Status status, String phase, int progress) {
        job.setStatus(status);
        job.setCurrentPhase(phase);
        job.setProgress(progress);
        jobRepo.save(job);
        emit(job.getId(), "progress", mapper.createObjectNode()
            .put("phase", phase).put("progress", progress).toString());
    }

    private void emit(String jobId, String type, String data) {
        Sinks.Many<ServerSentEvent<String>> sink = sinks.get(jobId);
        if (sink != null) {
            sink.tryEmitNext(ServerSentEvent.<String>builder()
                .event(type).data(data).build());
        }
    }

    private void saveAsset(String jobId, String type, String value, String ip,
                           String asn, String country, String org, boolean active) {
        if (value == null || value.isBlank()) return;
        DiscoveredAsset asset = new DiscoveredAsset();
        asset.setId(UUID.randomUUID().toString());
        asset.setJobId(jobId);
        asset.setType(type);
        asset.setValue(value);
        asset.setIp(ip);
        asset.setAsn(asn);
        asset.setCountry(country);
        asset.setOrg(org);
        asset.setActive(active);
        assetRepo.save(asset);
    }

    private void saveFinding(String jobId, String asset, String category,
                             String title, String description, String severity,
                             String evidence, String remediation) {
        AttackFinding f = new AttackFinding();
        f.setId(UUID.randomUUID().toString());
        f.setJobId(jobId);
        f.setAssetValue(asset);
        f.setCategory(category);
        f.setTitle(title);
        f.setDescription(description);
        f.setSeverity(severity);
        f.setEvidence(evidence);
        f.setRemediation(remediation);
        findingRepo.save(f);
        emit(jobId, "finding", mapper.createObjectNode()
            .put("severity", severity).put("title", title).put("asset", asset).toString());
    }
}
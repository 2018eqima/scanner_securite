package org.eqima.scanner.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.net.InetAddress;
import java.util.*;

@Service
public class DnsReconService {

    private static final Logger log = LoggerFactory.getLogger(DnsReconService.class);

    /** Common subdomains to brute-force */
    private static final List<String> WORDLIST = List.of(
        "www", "mail", "smtp", "pop", "imap", "ftp", "sftp", "ssh", "vpn",
        "api", "api2", "api-v1", "api-v2", "app", "app2", "admin", "portal",
        "dev", "staging", "preprod", "prod", "test", "qa", "uat", "demo",
        "blog", "shop", "store", "cdn", "static", "assets", "media", "images",
        "auth", "login", "sso", "oauth", "id", "account", "accounts",
        "dashboard", "panel", "control", "manage", "management", "console",
        "git", "gitlab", "github", "jenkins", "ci", "cd", "build",
        "monitor", "grafana", "kibana", "elastic", "log", "logs", "metrics",
        "db", "database", "mysql", "postgres", "redis", "mongo", "cache",
        "ns1", "ns2", "mx", "mx1", "mx2", "email", "webmail", "autodiscover",
        "support", "help", "docs", "documentation", "status", "health",
        "internal", "intranet", "corp", "vpn2", "remote", "secure",
        "backup", "old", "legacy", "archive", "beta", "alpha"
    );

    public record DnsResult(
        String domain,
        List<String> aRecords,
        List<String> aaaaRecords,
        List<String> mxRecords,
        List<String> nsRecords,
        List<String> txtRecords,
        String spf,
        String dmarc,
        List<String> dkimSelectors,
        boolean axfrAttempted,
        List<String> subdomainsFromBruteForce
    ) {}

    public DnsResult recon(String domain) {
        log.info("DNS recon starting for {}", domain);

        List<String> a     = queryDns(domain, "A");
        List<String> aaaa  = queryDns(domain, "AAAA");
        List<String> mx    = queryDns(domain, "MX");
        List<String> ns    = queryDns(domain, "NS");
        List<String> txt   = queryDns(domain, "TXT");

        String spf   = txt.stream().filter(t -> t.startsWith("v=spf")).findFirst().orElse(null);
        String dmarc = queryDns("_dmarc." + domain, "TXT").stream()
                           .filter(t -> t.startsWith("v=DMARC")).findFirst().orElse(null);

        // Common DKIM selectors
        List<String> dkimFound = new ArrayList<>();
        for (String sel : List.of("default", "google", "mail", "dkim", "k1", "s1", "s2", "selector1", "selector2")) {
            List<String> r = queryDns(sel + "._domainkey." + domain, "TXT");
            if (!r.isEmpty()) dkimFound.add(sel + " → " + r.get(0));
        }

        // Brute-force subdomain resolution
        List<String> bruteFound = new ArrayList<>();
        for (String word : WORDLIST) {
            String sub = word + "." + domain;
            try {
                InetAddress.getByName(sub);
                bruteFound.add(sub);
                log.debug("Brute-force found: {}", sub);
            } catch (Exception ignored) {}
        }

        log.info("DNS recon done for {}: {} A, {} MX, {} NS, {} TXT, {} brute subdomains",
            domain, a.size(), mx.size(), ns.size(), txt.size(), bruteFound.size());

        return new DnsResult(domain, a, aaaa, mx, ns, txt, spf, dmarc, dkimFound, false, bruteFound);
    }

    public List<String> queryDns(String name, String type) {
        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            env.put("java.naming.provider.url", "dns://8.8.8.8");
            env.put("com.sun.jndi.dns.timeout.initial", "3000");
            env.put("com.sun.jndi.dns.timeout.retries", "1");
            DirContext ctx = new InitialDirContext(env);
            Attributes attrs = ctx.getAttributes(name, new String[]{type});
            Attribute attr = attrs.get(type);
            List<String> results = new ArrayList<>();
            if (attr != null) {
                NamingEnumeration<?> vals = attr.getAll();
                while (vals.hasMore()) {
                    results.add(vals.next().toString().trim());
                }
            }
            ctx.close();
            return results;
        } catch (Exception e) {
            log.debug("DNS {} query failed for {}: {}", type, name, e.getMessage());
            return List.of();
        }
    }
}
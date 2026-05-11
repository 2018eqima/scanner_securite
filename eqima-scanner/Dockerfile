# ── Stage 1 : Build ──────────────────────────────────────────────────────────
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app

# Résoudre les dépendances en cache (layer stable)
COPY pom.xml .
RUN mvn dependency:go-offline -q

# Build
COPY src ./src
RUN mvn clean package -DskipTests -q

# ── Stage 2 : Runtime ─────────────────────────────────────────────────────────
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

RUN addgroup -S scanner && adduser -S scanner -G scanner
USER scanner

COPY --from=build /app/target/*.jar app.jar

EXPOSE 8085

ENTRYPOINT ["java", \
  "-XX:+UseZGC", \
  "-XX:+ZGenerational", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "app.jar"]
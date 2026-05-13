FROM eclipse-temurin:17-jdk AS build
WORKDIR /workspace

COPY .mvn .mvn
COPY mvnw pom.xml ./
RUN chmod +x mvnw

COPY src src
RUN ./mvnw -q -DskipTests package

FROM eclipse-temurin:17-jre
WORKDIR /app

# Install trivy CLI for CVE scanning and DejaVu font for PDF generation
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates fontconfig bzip2 \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && mkdir -p /tmp/fonts /usr/share/fonts/truetype/dejavu \
    && curl -sfL -o /tmp/fonts/dejavu.tar.bz2 "https://github.com/dejavu-fonts/dejavu-fonts/releases/download/version_2_37/dejavu-fonts-ttf-2.37.tar.bz2" \
    && tar -xjf /tmp/fonts/dejavu.tar.bz2 -C /tmp/fonts \
    && cp /tmp/fonts/dejavu-fonts-ttf-2.37/ttf/DejaVuSans.ttf /usr/share/fonts/truetype/dejavu/ \
    && fc-cache -fv \
    && rm -rf /tmp/fonts \
    && apt-get purge -y curl bzip2 && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

COPY --from=build /workspace/target/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/app.jar"]

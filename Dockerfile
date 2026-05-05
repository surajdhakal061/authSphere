# Build stage
FROM gradle:9.4.0-jdk21-ubi10 AS build
WORKDIR /app
COPY build.gradle settings.gradle ./
RUN gradle dependencies --no-daemon
COPY . .
RUN gradle bootJar --no-daemon

# Run stage
FROM openjdk:21-ea-21-slim
WORKDIR /app
COPY --from=build /app/build/libs/*.jar authsphere.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "authsphere.jar"]
FROM gradle:9.4.0-jdk21-ubi10
WORKDIR /app
COPY . .
RUN gradle bootJar --no-daemon --stacktrace
EXPOSE 8080
CMD ["java", "-jar", "build/libs/*.jar"]
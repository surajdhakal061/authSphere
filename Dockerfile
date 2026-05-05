FROM gradle:8.5-jdk21
WORKDIR /app
COPY . .
RUN gradle bootJar --no-daemon --stacktrace
EXPOSE 8080
CMD ["java", "-jar", "build/libs/*.jar"]
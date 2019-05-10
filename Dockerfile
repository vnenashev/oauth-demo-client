#
# Build stage
#
FROM maven:3.6.1-jdk-8-slim AS build
COPY pom.xml /app/
RUN mvn -f /app/pom.xml dependency:go-offline
COPY src /app/src
RUN mvn -f /app/pom.xml clean package

#
# Package stage
#
FROM openjdk:8-jre-slim
COPY --from=build /app/target/oauth-demo-client.jar /usr/local/lib/oauth-demo-client.jar
EXPOSE 8081
ENTRYPOINT ["java","-jar","/usr/local/lib/oauth-demo-client.jar"]

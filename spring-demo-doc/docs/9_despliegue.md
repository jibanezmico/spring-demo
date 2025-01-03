# Despliegue de Aplicaciones Spring Boot en Entornos de Producción

## Preparación para el Despliegue

### Construcción del paquete (JAR o WAR)
Para desplegar una aplicación Spring Boot, primero necesitas construir el paquete de tu aplicación. Esto puede ser un archivo JAR (Java ARchive) o un archivo WAR (Web Application Archive). Utiliza herramientas de construcción como Maven o Gradle para este propósito.

Con Maven, puedes construir el paquete ejecutando el siguiente comando en la raíz de tu proyecto:
```sh
mvn clean package
```
Este comando limpiará cualquier construcción previa y empaquetará tu aplicación en un archivo JAR o WAR, dependiendo de tu configuración.

Con Gradle, el comando equivalente es:
```sh
./gradlew build
```
Este comando también limpiará y construirá tu proyecto, generando el archivo JAR o WAR en el directorio `build/libs`.

### Configuración para producción: propiedades, perfiles y logs
Es crucial configurar tu aplicación adecuadamente para el entorno de producción. Esto incluye la configuración de propiedades, perfiles y logs.

- **Propiedades**: Crea un archivo `application-prod.properties` en el directorio `src/main/resources`. Este archivo contendrá las propiedades específicas para el entorno de producción, como configuraciones de base de datos, URLs de servicios externos, etc.

- **Perfiles**: Utiliza perfiles para separar las configuraciones de desarrollo y producción. Puedes activar el perfil de producción añadiendo el parámetro `--spring.profiles.active=prod` al comando de ejecución de tu aplicación.

- **Logs**: Configura los logs para producción asegurándote de que se capturen errores y eventos importantes. Puedes configurar el nivel de log y los appenders en el archivo `logback-spring.xml` o `application-prod.properties`.

## Despliegue en Servidores Locales

### Uso de Apache Tomcat o Jetty
Si decides empaquetar tu aplicación como un archivo WAR, puedes desplegarla en servidores de aplicaciones como Apache Tomcat o Jetty.

- Empaqueta tu aplicación como un archivo WAR utilizando Maven o Gradle.
- Copia el archivo WAR generado en el directorio `webapps` de tu instalación de Tomcat o Jetty.
- Inicia el servidor y tu aplicación estará disponible en el contexto configurado.

### Ejecución como aplicación standalone
Otra opción es empaquetar tu aplicación como un archivo JAR y ejecutarla como una aplicación standalone.

1. Empaqueta tu aplicación como un archivo JAR utilizando Maven o Gradle.
- Ejecuta el archivo JAR usando el siguiente comando:
```sh
java -jar tu-aplicacion.jar
```
Esto iniciará un servidor embebido (como Tomcat o Jetty) y tu aplicación estará disponible en el puerto configurado (por defecto, el puerto 8080).

## Despliegue en la Nube

### Introducción a plataformas cloud (AWS, GCP)
Desplegar aplicaciones en la nube ofrece ventajas como escalabilidad, alta disponibilidad y gestión simplificada. Algunas de las plataformas cloud más populares son AWS y GCP.

- **AWS (Amazon Web Services)**: Ofrece una amplia gama de servicios para el despliegue y escalado de aplicaciones, incluyendo EC2, Elastic Beanstalk, y RDS.
- **GCP (Google Cloud Platform)**: Proporciona herramientas y servicios para desplegar aplicaciones en la nube, como Google App Engine, Kubernetes Engine, y Cloud SQL.

## Contenedores con Docker

### Crear un Dockerfile para la aplicación
Docker permite empaquetar tu aplicación y sus dependencias en un contenedor, asegurando que se ejecute de manera consistente en cualquier entorno. Para crear un contenedor Docker para tu aplicación Spring Boot, necesitas definir un Dockerfile.

Ejemplo básico de Dockerfile:
```Dockerfile
FROM openjdk:11-jre-slim
COPY target/tu-aplicacion.jar app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
```
Este Dockerfile utiliza una imagen base de OpenJDK 11, copia el archivo JAR de tu aplicación en el contenedor y define el comando de entrada para ejecutar la aplicación.

### Despliegue de contenedores con Docker Compose
Docker Compose permite definir y ejecutar aplicaciones multi-contenedor. Puedes definir un archivo `docker-compose.yml` para gestionar múltiples contenedores.

Ejemplo básico de `docker-compose.yml`:
```yaml
version: '3'
services:
  app:
    image: tu-imagen
    ports:
      - "8080:8080"
```
Este archivo define un servicio llamado `app` que utiliza la imagen de tu aplicación y expone el puerto 8080.

## Monitorización y Escalabilidad

### Herramientas como Spring Boot Actuator
Spring Boot Actuator añade endpoints de monitorización a tu aplicación, permitiéndote obtener información sobre su estado y métricas. Para habilitar Actuator, añade la dependencia en tu `pom.xml` o `build.gradle`.

Ejemplo de configuración en `pom.xml`:
```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```
Configura los endpoints en tu archivo `application.properties` o `application.yml`. Por ejemplo, para habilitar el endpoint de salud:
```properties
management.endpoints.web.exposure.include=health
```
Accede al endpoint `/actuator/health` para verificar el estado de la aplicación.

### Escalado horizontal y vertical
El escalado es crucial para manejar el aumento de tráfico y mejorar el rendimiento de tu aplicación.

- **Escalado horizontal**: Añade más instancias de tu aplicación para distribuir la carga. Esto se puede lograr fácilmente en plataformas cloud y con herramientas de orquestación de contenedores como Kubernetes.
- **Escalado vertical**: Aumenta los recursos (CPU, memoria) de la instancia existente para mejorar el rendimiento. Esto puede ser útil para aplicaciones que requieren más recursos en lugar de más instancias.

Implementar estrategias de escalado adecuadas asegurará que tu aplicación pueda manejar el crecimiento y mantener un rendimiento óptimo.
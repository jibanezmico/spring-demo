# Introducción a Spring Boot y conceptos clave

## Introducción a Conceptos Básicos de Spring

### ¿Qué es Spring?

Spring es un framework de código abierto para el desarrollo de aplicaciones en Java que promueve buenas prácticas de diseño. Su propósito principal es reducir la complejidad en la configuración y el desarrollo de aplicaciones empresariales, permitiendo a los desarrolladores centrarse en la lógica de negocio.

Spring es muy versátil y se puede usar para desarrollar aplicaciones de cualquier tipo, desde simples herramientas hasta sistemas empresariales complejos.

### Framework vs. Librería

Un framework como Spring establece un conjunto de reglas y estructuras que el desarrollador debe seguir, ofreciendo flexibilidad pero también dirección. A diferencia de una librería, que simplemente provee funciones reutilizables, un framework como Spring organiza y gestiona el flujo de control de la aplicación.

### Historia de Spring

Spring fue creado en 2003 por Rod Johnson como una alternativa más sencilla y modular a las especificaciones complejas de Java EE. Su objetivo inicial era facilitar el desarrollo de aplicaciones empresariales al proporcionar un enfoque más ligero y flexible.

### Introducción a Spring Boot

Spring Boot es una extensión del framework Spring diseñada para simplificar el desarrollo y despliegue de aplicaciones. Es ideal tanto para principiantes como para desarrolladores experimentados que deseen reducir la complejidad de configuración.

#### Características principales

- **Configuración automática**: Spring Boot configura automáticamente los componentes necesarios en función de las dependencias incluidas en el proyecto.
- **Servidores embebidos**: Integración con servidores como Tomcat o Jetty, lo que elimina la necesidad de configurarlos externamente.
- **Aplicaciones listas para producción**: Incluye herramientas para monitoreo, métricas y análisis de rendimiento.

#### Ejemplo práctico: "Hello World"

```java
@SpringBootApplication
public class HelloWorldApplication {
    public static void main(String[] args) {
        SpringApplication.run(HelloWorldApplication.class, args);
    }
}
```

### Uso de Spring Initializr

Spring Initializr es una herramienta que permite generar proyectos Spring Boot con las dependencias necesarias. Aquí se explica cómo utilizar Spring Initializr para crear un nuevo proyecto:

- **Acceder a Spring Initializr**:
      - Abre un navegador web y navega a [Spring Initializr](https://start.spring.io/).

- **Configurar el Proyecto**:
      - Selecciona las opciones de configuración del proyecto, como el nombre del grupo, el nombre del artefacto, la versión de Java, etc.
      - Añade las dependencias necesarias, como `Spring Web`, `Spring Data JPA`, `Spring Boot DevTools`, etc. Por ahora basta con Spring Web.

- **Generar el Proyecto**:
      - Haz clic en el botón "Generate" para descargar el proyecto generado.
      - Descomprime el archivo descargado y abre el proyecto en tu IDE favorito.

## Principales Proyectos de Spring

### Spring Boot

Spring Boot es una herramienta que simplifica significativamente el desarrollo con Spring, eliminando la necesidad de configuraciones extensas y repetitivas. Está diseñado para agilizar la creación de aplicaciones listas para producción, especialmente en entornos de microservicios.

### Spring Web

Spring Web es un módulo de Spring que facilita la creación de aplicaciones web y servicios RESTful. Proporciona soporte para controladores, vistas y modelos, y permite manejar solicitudes HTTP de manera sencilla.

#### Características principales

- **Controladores RESTful**: Facilita la creación de APIs RESTful mediante anotaciones como `@RestController`.
- **Manejo de solicitudes HTTP**: Permite manejar solicitudes HTTP GET, POST, PUT, DELETE, etc.
- **Soporte para vistas**: Integra con tecnologías de vistas como Thymeleaf, JSP, etc.

### Spring Data

Spring Data facilita la interacción con bases de datos mediante la definición de repositorios que encapsulan las operaciones CRUD y consultas personalizadas. Su objetivo es reducir la cantidad de código repetitivo en las capas de acceso a datos.

#### Características principales

- **Repositorios predefinidos**: Proporciona interfaces como `JpaRepository` que permiten realizar operaciones estándar sin necesidad de implementación manual.
- **Consultas personalizadas**: Permite definir consultas específicas mediante nombres de métodos o anotaciones como `@Query`.
- **Compatibilidad con múltiples bases de datos**: Incluye soporte para MySQL, PostgreSQL, MongoDB, Cassandra, entre otras.
- **Auditoría**: Proporciona soporte para auditoría de entidades, permitiendo rastrear cambios en los datos.
- **Paginación y ordenación**: Facilita la paginación y ordenación de resultados de consultas.

### Spring Security

Spring Security es un marco que proporciona herramientas avanzadas para garantizar la autenticación, autorización y protección contra ataques comunes en aplicaciones Java.

#### Características principales

- **Gestión de roles y permisos**: Controla el acceso a diferentes partes de la aplicación según roles definidos.
- **Protección avanzada**: Incluye medidas contra ataques de fuerza bruta, CSRF y XSS.
- **Compatibilidad**: Funciona con autenticación tradicional basada en formularios y sistemas modernos como OAuth2 o JWT.
- **Integración con Spring Boot**: Se integra fácilmente con aplicaciones Spring Boot para proporcionar seguridad de manera rápida y sencilla.
- **Personalización**: Permite personalizar la configuración de seguridad según las necesidades específicas de la aplicación.

### Spring Cloud

Spring Cloud extiende las funcionalidades de Spring para abordar los desafíos de arquitecturas distribuidas y microservicios. Este marco se enfoca en la gestión de configuración, descubrimiento de servicios, balanceo de carga y comunicación entre servicios.

#### Características principales

- **Gestión de configuración**: Centraliza la configuración de aplicaciones distribuidas.
- **Descubrimiento de servicios**: Permite que los servicios se registren y descubran entre sí.
- **Balanceo de carga**: Distribuye el tráfico de manera equitativa entre instancias de servicios.
- **Comunicación entre servicios**: Facilita la comunicación entre servicios mediante herramientas como Feign y Ribbon.

## Material Avanzado

### Configuración Avanzada de Spring Boot

Spring Boot permite configurar perfiles para gestionar diferentes configuraciones en distintos entornos (desarrollo, producción, etc.). Aquí se explica cómo configurar perfiles y propiedades externas.

#### Configuración de Perfiles

- **Crear Archivos de Configuración por Perfil**:
      - Crear archivos de configuración específicos para cada perfil, como `application-dev.properties` y `application-prod.properties`.

```properties
# application-dev.properties
server.port=8081
spring.datasource.url=jdbc:h2:mem:devdb
```

```properties
# application-prod.properties
server.port=8080
spring.datasource.url=jdbc:mysql://localhost/proddb
```

- **Activar un Perfil**:
      - Activar un perfil específico utilizando la propiedad `spring.profiles.active` en el archivo `application.properties` o mediante una variable de entorno.

```properties
# application.properties
spring.profiles.active=dev
```

#### Configuración de Propiedades Externas

Spring Boot permite cargar propiedades desde archivos externos o variables de entorno.

- **Cargar Propiedades desde un Archivo Externo**:
      - Especificar la ubicación del archivo de propiedades externo utilizando la propiedad `spring.config.location`.

```properties
# application.properties
spring.config.location=classpath:/config/application-external.properties
```

- **Utilizar Variables de Entorno**:
      - Definir variables de entorno en el sistema operativo y acceder a ellas en el archivo de configuración.

```properties
# application.properties
spring.datasource.url=${DATASOURCE_URL}
```

### Monitoreo y Métricas

Spring Boot Actuator proporciona funcionalidades para monitorear y gestionar aplicaciones en producción. Aquí se explica cómo habilitar y configurar Actuator.

#### Habilitar Actuator

- **Agregar la Dependencia de Actuator**:
      - Añadir la dependencia `spring-boot-starter-actuator` en el archivo `pom.xml`.

```xml
<dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```

- **Configurar Actuator**:
      - Configurar Actuator en el archivo `application.properties`.

```properties
management.endpoints.web.exposure.include=*
management.endpoint.health.show-details=always
```

#### Monitoreo de la Salud de la Aplicación

Actuator proporciona un endpoint `/actuator/health` para monitorear la salud de la aplicación.

- **Acceder al Endpoint de Salud**:
      - Iniciar la aplicación Spring Boot.
      - Acceder al endpoint de salud en `http://localhost:8080/actuator/health`.

#### Métricas de Rendimiento

Actuator proporciona un endpoint `/actuator/metrics` para acceder a métricas de rendimiento.

- **Acceder al Endpoint de Métricas**:
      - Iniciar la aplicación Spring Boot.
      - Acceder al endpoint de métricas en `http://localhost:8080/actuator/metrics`.

#### Explicación del Código

- `spring.profiles.active`: Propiedad utilizada para activar un perfil específico.
- `spring.config.location`: Propiedad utilizada para especificar la ubicación de un archivo de propiedades externo.
- `management.endpoints.web.exposure.include`: Propiedad utilizada para exponer todos los endpoints de Actuator.
- `management.endpoint.health.show-details`: Propiedad utilizada para mostrar detalles en el endpoint de salud.

#### Beneficios de Usar Actuator

- **Monitoreo en Tiempo Real**: Proporciona información en tiempo real sobre la salud y el rendimiento de la aplicación.
- **Gestión Simplificada**: Facilita la gestión de aplicaciones en producción mediante endpoints de administración.
- **Integración con Herramientas de Monitoreo**: Se integra fácilmente con herramientas de monitoreo como Prometheus y Grafana.

#### Actividad Práctica

- **Configurar Perfiles en Spring Boot**:
      - Crear archivos de configuración específicos para cada perfil.
      - Activar un perfil específico utilizando la propiedad `spring.profiles.active`.

- **Habilitar y Configurar Actuator**:
      - Añadir la dependencia `spring-boot-starter-actuator`.
      - Configurar Actuator en el archivo `application.properties`.
      - Acceder a los endpoints de salud y métricas para monitorear la aplicación.


## Capítulo 1: Introducción a Spring Boot y Configuración del Proyecto

### Introducción

Spring Boot es un framework que facilita la creación de aplicaciones Java basadas en Spring. Proporciona configuración automática y servidores embebidos, lo que permite desarrollar aplicaciones rápidamente.

### Actividad Práctica

- **Crear un proyecto Spring Boot**:
      - Utiliza Spring Initializr para crear un nuevo proyecto llamado "spring-demo" con las dependencias necesarias, por ejemplo, puedes añadir Spring Web.

- **Estructura del Proyecto y Explicación de Componentes**:
      - **src/main/java**: Contiene el código fuente de la aplicación.
        - **com.example.springdemo**: Paquete base donde se encuentra la clase principal.
        - **SpringDemoApplication.java**: Clase principal de la aplicación con la anotación `@SpringBootApplication`.
```java
@SpringBootApplication
public class SpringDemoApplication {
    private static final Logger logger = LoggerFactory.getLogger(SpringDemoApplication.class);

    public static void main(String[] args) {
        logger.info("Iniciando la aplicación Spring Boot");
        SpringApplication.run(SpringDemoApplication.class, args);
        logger.info("Aplicación Spring Boot iniciada");
    }
}
```
 La anotación `@SpringBootApplication` es una combinación de tres anotaciones: `@Configuration`, `@EnableAutoConfiguration`, y `@ComponentScan`. Esta anotación marca la clase como la principal para la configuración de Spring Boot. El método `main` utiliza `SpringApplication.run` para lanzar la aplicación.

   - **src/main/resources**: Contiene recursos estáticos y archivos de configuración.
     - **application.properties**: Archivo de configuración de la aplicación.
``` properties
# Configuración de ejemplo
server.port=8080
spring.application.name=spring-demo
```
 El archivo `application.properties` se utiliza para configurar diversas propiedades de la aplicación, como el puerto del servidor y el nombre de la aplicación.

   - **src/test/java**: Contiene las pruebas unitarias de la aplicación.
   - **pom.xml**: Archivo de configuración de Maven que gestiona las dependencias del proyecto.
```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <!-- Otras dependencias -->
</dependencies>
```
El archivo `pom.xml` es utilizado por Maven para gestionar las dependencias del proyecto. En este ejemplo, se incluye la dependencia `spring-boot-starter-web` para añadir soporte para aplicaciones web.

- **Poner en ejecución el proyecto**:
     - Abre una terminal en el directorio raíz del proyecto.
     - Ejecuta el siguiente comando para compilar y ejecutar la aplicación:

```sh
./mvnw spring-boot:run
```
   - La aplicación estará disponible en `http://localhost:8080`.

### Uso de Logger en Spring Boot

El uso de un Logger es esencial para registrar eventos importantes y errores en la aplicación. Spring Boot utiliza `SLF4J` como interfaz de registro y `Logback` como implementación predeterminada. Aquí se muestra cómo configurar y usar un Logger en una clase de servicio:

- **Agregar la dependencia de SLF4J en `pom.xml`**:
```xml
<dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>slf4j-api</artifactId>
</dependency>
<dependency>
    <groupId>ch.qos.logback</groupId>
    <artifactId>logback-classic</artifactId>
</dependency>
```

- **Configurar el Logger en una clase de servicio**:
```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class ExampleService {
    private static final Logger logger = LoggerFactory.getLogger(ExampleService.class);

    public void exampleMethod() {
        logger.info("Método exampleMethod ejecutado");
        logger.debug("Debugging exampleMethod");
        try {
            // ...existing code...
        } catch (Exception e) {
            logger.error("Error en exampleMethod: {}", e.getMessage());
        }
    }
}
```

### Configuración de Niveles de Registro en `application.properties`

Para configurar diferentes niveles de registro (INFO, DEBUG, ERROR) en `application.properties`, se pueden añadir las siguientes propiedades:

```properties
logging.level.root=INFO
logging.level.com.example.springdemo=DEBUG
logging.file.name=logs/spring-demo.log
```

### Ejemplos de Pruebas Unitarias

Las pruebas unitarias son esenciales para asegurar que el código funcione correctamente y para detectar errores de manera temprana. Aquí se muestra cómo escribir y ejecutar pruebas unitarias en Spring Boot:

- **Agregar Dependencias de Pruebas en `pom.xml`**:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-test</artifactId>
    <scope>test</scope>
</dependency>
```

- **Escribir una Prueba Unitaria para un Controlador**:
```java
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(HolaMundoController.class)
public class HolaMundoControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void testHolaMundo() throws Exception {
        mockMvc.perform(get("/api/hola"))
                .andExpect(status().isOk())
                .andExpect(content().string("Hola Mundo"));
    }
}
```

- **Escribir una Prueba Unitaria para un Servicio**:
```java
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
public class ExampleServiceTest {

    @Autowired
    private ExampleService exampleService;

    @Test
    public void testExampleMethod() {
        exampleService.exampleMethod();
        // Verificar el comportamiento esperado
        assertThat(true).isTrue();
    }
}
```

### Explicación del Código

- `@SpringBootApplication`: Esta anotación es una combinación de tres anotaciones: `@Configuration`, `@EnableAutoConfiguration`, y `@ComponentScan`. Marca la clase como la principal para la configuración de Spring Boot.
- `SpringApplication.run(SpringDemoApplication.class, args)`: Este método lanza la aplicación Spring Boot.
- `Logger`: Utilizado para registrar eventos importantes y errores en la aplicación.
- `@WebMvcTest`: Anotación utilizada para pruebas unitarias de controladores.
- `MockMvc`: Utilizado para realizar solicitudes HTTP simuladas en pruebas unitarias.
- `@SpringBootTest`: Anotación utilizada para pruebas unitarias de servicios.

### Beneficios de Usar Spring Boot

- **Configuración Automática**: Spring Boot configura automáticamente los componentes necesarios en función de las dependencias incluidas en el proyecto.
- **Servidores Embebidos**: Integración con servidores como Tomcat o Jetty, lo que elimina la necesidad de configurarlos externamente.
- **Aplicaciones Listas para Producción**: Incluye herramientas para monitoreo, métricas y análisis de rendimiento.

### Actividad Práctica

- **Explorar la Estructura del Proyecto**:
      - Navegar por los directorios y archivos del proyecto para familiarizarse con la estructura del proyecto Spring Boot.
      - Revisar el archivo `application.properties` y agregar configuraciones adicionales según sea necesario.

### Posibles Errores Comunes

- **Error de Conexión al Servidor**:
      - **Solución**: Verificar que el puerto configurado en `application.properties` no esté en uso por otra aplicación.

- **Dependencias**:
      - **Solución**: Asegurarse de que todas las dependencias necesarias estén incluidas en el archivo `pom.xml` y ejecutar `mvn clean install` para actualizar el proyecto.


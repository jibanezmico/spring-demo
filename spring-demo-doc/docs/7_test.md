# 6. Pruebas y Depuración

## Introducción a las Pruebas en Spring Boot

Las pruebas son una parte crucial del ciclo de desarrollo de software. Aseguran que el código funcione como se espera y ayudan a identificar problemas antes de que lleguen a producción. En el ecosistema de Spring Boot, las herramientas más comunes para realizar pruebas son JUnit, Mockito y Spring Boot Test.

## Pruebas Unitarias y de Integración

### Pruebas Unitarias

Las pruebas unitarias son esenciales para asegurar que cada componente de la aplicación funcione correctamente de manera aislada. En aplicaciones Spring Boot, JUnit y Mockito son herramientas populares para escribir y ejecutar pruebas unitarias.

#### Configuración de JUnit y Mockito

Para comenzar, asegúrate de tener las dependencias necesarias en tu archivo `pom.xml`:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-test</artifactId>
    <scope>test</scope>
</dependency>
<dependency>
    <groupId>org.mockito</groupId>
    <artifactId>mockito-core</artifactId>
    <scope>test</scope>
</dependency>
```

#### Ejemplo de Prueba Unitaria

```java
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(MockitoExtension.class)
public class MiServicioTest {

    @Mock
    private MiRepositorio miRepositorio;

    @InjectMocks
    private MiServicio miServicio;

    @Test
    public void testObtenerDatos() {
        when(miRepositorio.obtenerDatos()).thenReturn("datos de prueba");

        String resultado = miServicio.obtenerDatos();

        assertEquals("datos de prueba", resultado);
    }
}
```

### Pruebas de Integración

Las pruebas de integración verifican que diferentes partes de la aplicación funcionen juntas correctamente. En Spring Boot, estas pruebas suelen involucrar el contexto de la aplicación completo.

#### Configuración para Pruebas de Integración

Para realizar pruebas de integración, puedes utilizar bases de datos en memoria como H2. Asegúrate de tener la dependencia en tu archivo `pom.xml`:

```xml
<dependency>
    <groupId>com.h2database</groupId>
    <artifactId>h2</artifactId>
    <scope>test</scope>
</dependency>
```

#### Ejemplo de Prueba de Integración

```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
@SpringBootTest
public class MiAplicacionTests {

    @Autowired
    private MiServicio miServicio;

    @Test
    public void contextLoads() {
        assertThat(miServicio).isNotNull();
    }
}
```

## Ejecución de Pruebas

### Integración con Herramientas de CI/CD

Para integrar las pruebas con herramientas de CI/CD, asegúrate de que tu pipeline ejecute los tests automáticamente. Por ejemplo, en un archivo de configuración de Jenkins:

```groovy
pipeline {
    agent any
    stages {
        stage('Test') {
            steps {
                sh './mvnw test'
            }
        }
    }
}
```

### Reportes de Pruebas

Los reportes de pruebas son esenciales para entender el estado de las pruebas. Puedes configurar Maven Surefire Plugin para generar reportes:

```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-surefire-plugin</artifactId>
    <version>2.22.2</version>
    <configuration>
        <reportsDirectory>${project.build.directory}/surefire-reports</reportsDirectory>
    </configuration>
</plugin>
```

## Depuración y Monitoreo

### Depuración

La depuración es una parte crucial del desarrollo de software. Spring Boot facilita la depuración con su soporte para logs y herramientas de depuración.

#### Configuración de Logs

Spring Boot utiliza `Logback` como el motor de logging por defecto. Puedes configurar los logs en el archivo `application.properties`:

```properties
logging.level.org.springframework=DEBUG
logging.level.com.miapp=DEBUG
```

### Monitoreo

El monitoreo de aplicaciones en producción es vital para mantener el rendimiento y la disponibilidad. Spring Boot Actuator proporciona endpoints para monitorear y gestionar la aplicación.

#### Configuración de Spring Boot Actuator

Añade la dependencia en tu `pom.xml`:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```

#### Endpoints de Actuator

Actuator expone varios endpoints útiles, como `/actuator/health` y `/actuator/metrics`. Puedes configurarlos en `application.properties`:

```properties
management.endpoints.web.exposure.include=health,info,metrics
```

### Ejemplo de Uso de Actuator

Accede a los endpoints de Actuator para obtener información sobre el estado de la aplicación:

```sh
curl http://localhost:8080/actuator/health
curl http://localhost:8080/actuator/metrics
```

Estos endpoints proporcionan información valiosa para monitorear y mantener la salud de tu aplicación Spring Boot en producción.
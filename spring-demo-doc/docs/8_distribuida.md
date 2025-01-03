# 8. Introducción a la programación distribuida

## Objetivo
Introducir conceptos de programación distribuida y su implementación en Spring Boot.

## Conceptos Básicos
La programación paralela se enfoca en ejecutar múltiples tareas simultáneamente en un solo sistema, utilizando múltiples núcleos de CPU. Un ejemplo de esto es el procesamiento de imágenes, donde cada núcleo procesa una parte de la imagen.

Por otro lado, la programación distribuida implica múltiples sistemas trabajando juntos en una red para completar tareas. Un ejemplo de esto es un motor de búsqueda en línea, donde diferentes servidores indexan diferentes partes de la web para proporcionar resultados de búsqueda rápidos y relevantes.

Ventajas de los sistemas distribuidos incluyen la escalabilidad, que es la capacidad de añadir más nodos para manejar más carga. Por ejemplo, en un sistema de comercio electrónico, se pueden añadir más servidores para manejar más usuarios. También ofrecen tolerancia a fallos, ya que si un nodo falla, otros pueden continuar el trabajo. Por ejemplo, si un servidor se cae, otros servidores pueden tomar su lugar. Además, ofrecen flexibilidad, permitiendo que diferentes nodos ejecuten diferentes tareas. Por ejemplo, un nodo puede manejar la autenticación de usuarios mientras otro maneja las transacciones.

Sin embargo, los sistemas distribuidos también presentan desafíos. La gestión de múltiples nodos y su comunicación puede ser compleja, por ejemplo, asegurar que todos los nodos estén sincronizados y se comuniquen correctamente. La latencia de red, o el tiempo de retraso en la comunicación entre nodos, puede ser un problema, especialmente en la comunicación entre servidores en diferentes ubicaciones geográficas. Finalmente, asegurar la consistencia de datos, es decir, que todos los nodos tengan la misma información, puede ser complicado. Por ejemplo, si un usuario actualiza su perfil, todos los nodos deben tener la información actualizada.

## Microservicios con Spring Boot
Spring Cloud proporciona herramientas para construir aplicaciones distribuidas y microservicios, facilitando la configuración, descubrimiento, balanceo de carga, y más. Por ejemplo, Spring Cloud Config para la gestión de configuración, Spring Cloud Netflix para el descubrimiento de servicios, y Spring Cloud Gateway para el enrutamiento de solicitudes.

Cada microservicio es una aplicación Spring Boot independiente que se comunica con otros servicios a través de APIs REST. Esto permite que cada servicio sea desarrollado, desplegado y escalado de manera independiente.

Ejemplo básico de un microservicio:
```java
@SpringBootApplication
public class ServicioClienteApplication {
    public static void main(String[] args) {
        SpringApplication.run(ServicioClienteApplication.class, args);
    }
}

@RestController
@RequestMapping("/cliente")
public class ClienteController {
    @GetMapping
    public String getCliente() {
        return "Cliente 1";
    }
}
```

## Comunicación entre Microservicios
RestTemplate es una clase de Spring para hacer llamadas HTTP sincrónicas. Es útil para realizar solicitudes HTTP simples y directas.

Feign es un cliente HTTP declarativo que facilita la comunicación entre microservicios. Permite definir interfaces y anotarlas para especificar las solicitudes HTTP.

Ejemplo de uso de RestTemplate:
```java
@RestController
public class ClienteController {
    @Autowired
    private RestTemplate restTemplate;

    @GetMapping("/cliente")
    public String getCliente() {
        return restTemplate.getForObject("http://servicio-cliente/cliente", String.class);
    }
}
```

Ejemplo de uso de Feign:
```java
@FeignClient(name = "servicio-cliente")
public interface ClienteFeignClient {
    @GetMapping("/cliente")
    String getCliente();
}

@RestController
public class ClienteController {
    @Autowired
    private ClienteFeignClient clienteFeignClient;

    @GetMapping("/cliente")
    public String getCliente() {
        return clienteFeignClient.getCliente();
    }
}
```

Ribbon es una biblioteca de balanceo de carga cliente que distribuye las solicitudes entre múltiples instancias de un servicio. Esto ayuda a distribuir la carga de trabajo y mejorar la disponibilidad del servicio.

Spring Cloud LoadBalancer es una alternativa más reciente y ligera que proporciona funcionalidad similar.

Ejemplo de configuración de Ribbon:
```java
@Bean
@LoadBalanced
public RestTemplate restTemplate() {
    return new RestTemplate();
}
```

## Gestión de Configuración
Spring Cloud Config Server permite centralizar la configuración de múltiples aplicaciones, almacenando las configuraciones en un repositorio Git. Esto facilita la gestión de configuraciones y asegura que todas las aplicaciones utilicen la misma configuración.

Ejemplo de configuración de Spring Cloud Config Server:
```yaml
# application.yml en Config Server
spring:
  cloud:
    config:
      server:
        git:
          uri: https://github.com/tu-repo/config-repo
```

Uso de perfiles para gestionar configuraciones específicas de entornos (dev, prod, etc.). Esto permite tener diferentes configuraciones para diferentes entornos sin necesidad de cambiar el código.

Ejemplo de configuración de perfiles:
```yaml
# application-dev.yml
server:
  port: 8081
```

## Pruebas de un Sistema Distribuido
Uso de herramientas como WireMock para simular servicios externos y probar la interacción entre microservicios. Esto permite probar cómo se comportan los servicios cuando interactúan con otros servicios.

Ejemplo de prueba con WireMock:
```java
@Test
public void testClienteService() {
    stubFor(get(urlEqualTo("/cliente"))
        .willReturn(aResponse()
            .withStatus(200)
            .withBody("Cliente 1")));

    String response = restTemplate.getForObject("http://localhost:8080/cliente", String.class);
    assertEquals("Cliente 1", response);
}
```

Implementación de pruebas de contrato para garantizar que los servicios se comuniquen correctamente y mantengan la consistencia de datos. Esto asegura que los servicios cumplan con los contratos definidos y se comporten como se espera.

Ejemplo de prueba de contrato:
```java
@SpringBootTest
public class ClienteContractTest {
    @Autowired
    private MockMvc mockMvc;

    @Test
    public void validateClienteContract() throws Exception {
        mockMvc.perform(get("/cliente"))
            .andExpect(status().isOk())
            .andExpect(content().string("Cliente 1"));
    }
}
```

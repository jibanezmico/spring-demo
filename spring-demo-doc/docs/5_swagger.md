## Capítulo 5: Documentación con Swagger

### Introducción a Swagger

Swagger es una herramienta para documentar y probar APIs RESTful. Proporciona una interfaz de usuario interactiva que permite a los desarrolladores explorar y probar los endpoints de la API de manera sencilla. Swagger facilita la creación de documentación detallada y actualizada de las APIs, lo que mejora la comunicación entre los equipos de desarrollo y otros stakeholders.

### Configuración de Swagger en Spring Boot

La configuración de Swagger se realiza en una clase anotada con `@Configuration`. Esta clase define un bean `Docket` que configura Swagger para escanear los controladores y generar la documentación de la API.

### Actividad Práctica

- **Configurar Swagger**:
      - Crear una clase de configuración para Swagger en el paquete `config`.

```java
@Configuration
@EnableSwagger2
public class SwaggerConfig {
    private static final Logger logger = LoggerFactory.getLogger(SwaggerConfig.class);

    @Bean
    public Docket api() {
        logger.info("Configurando Swagger Docket");
        return new Docket(DocumentationType.SWAGGER_2)
                .select()
                .apis(RequestHandlerSelectors.basePackage("com.demospring.security.controller"))
                .paths(PathSelectors.any())
                .build()
                .apiInfo(apiInfo());
    }

    private ApiInfo apiInfo() {
        logger.debug("Configurando ApiInfo");
        return new ApiInfoBuilder()
                .title("API de Seguridad")
                .description("Documentación de la API de Seguridad con Spring Boot y Swagger")
                .version("1.0.0")
                .build();
    }
}
```

   En esta configuración:
   - La anotación `@EnableSwagger2` habilita Swagger en la aplicación.
   - El método `api()` define un bean `Docket` que configura Swagger para escanear los controladores en el paquete `com.demospring.security.controller`.
   - El método `select()` permite personalizar qué controladores y rutas se incluirán en la documentación de Swagger.
   - `apis(RequestHandlerSelectors.basePackage("com.demospring.security.controller"))` especifica que solo se escanearán los controladores en el paquete `com.demospring.security.controller`.
   - `paths(PathSelectors.any())` indica que se incluirán todas las rutas en la documentación.
   - `apiInfo()` proporciona información adicional sobre la API, como el título, la descripción y la versión.
   - Se utiliza un Logger para registrar eventos importantes durante la configuración de Swagger.

   Una vez configurado, Swagger generará automáticamente la documentación de la API y proporcionará una interfaz de usuario interactiva en la ruta `/swagger-ui.html`.

### Personalización de Swagger para Mostrar Ejemplos Específicos

Para personalizar Swagger y mostrar ejemplos específicos en los endpoints, se pueden utilizar anotaciones como `@ApiOperation` y `@ApiResponses` en los controladores. Aquí hay un ejemplo:

```java
@RestController
@RequestMapping("/api/users")
public class UserController {
    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    @ApiOperation(value = "Obtener todos los usuarios", response = List.class)
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Usuarios obtenidos con éxito"),
        @ApiResponse(code = 401, message = "No autorizado"),
        @ApiResponse(code = 403, message = "Prohibido"),
        @ApiResponse(code = 404, message = "No encontrado")
    })
    @GetMapping
    public ResponseEntity<List<User>> getAllUsers() {
        logger.info("getAllUsers endpoint llamado");
        // ...existing code...
    }

    @ApiOperation(value = "Crear un nuevo usuario")
    @ApiResponses(value = {
        @ApiResponse(code = 201, message = "Usuario creado con éxito"),
        @ApiResponse(code = 400, message = "Solicitud incorrecta")
    })
    @PostMapping
    public ResponseEntity<User> createUser(@RequestBody User user) {
        logger.info("createUser endpoint llamado con datos: {}", user);
        // ...existing code...
    }
}
```

En este ejemplo:
- `@ApiOperation` describe la operación del endpoint.
- `@ApiResponses` define las posibles respuestas del endpoint, incluyendo códigos de estado y mensajes.
- `Logger`: Utilizado para registrar eventos importantes y errores en la aplicación.

### Generar un Cliente API desde la Documentación Swagger

Swagger también permite generar clientes API automáticamente desde la documentación. Aquí hay un ejemplo de cómo hacerlo:

- **Acceder a la Interfaz de Usuario de Swagger**:
      - Inicia la aplicación Spring Boot.
      - Abre un navegador web y navega a `http://localhost:8080/swagger-ui.html`.

- **Generar el Cliente API**:
      - En la interfaz de usuario de Swagger, haz clic en el botón "Generate Client".
      - Selecciona el lenguaje de programación deseado (por ejemplo, Java, Python, etc.).
      - Descarga el código del cliente API generado.

Este cliente API puede ser utilizado para interactuar con la API documentada sin necesidad de escribir código adicional para las solicitudes HTTP.

### Explicación del Código

- `@Configuration`: Indica que esta clase es una clase de configuración de Spring.
- `@EnableSwagger2`: Habilita Swagger en la aplicación.
- `Docket api()`: Define un bean `Docket` que configura Swagger para escanear los controladores y generar la documentación de la API.
- `select()`: Permite personalizar qué controladores y rutas se incluirán en la documentación de Swagger.
- `apis(RequestHandlerSelectors.basePackage("com.demospring.security.controller"))`: Especifica que solo se escanearán los controladores en el paquete `com.demospring.security.controller`.
- `paths(PathSelectors.any())`: Indica que se incluirán todas las rutas en la documentación.

### Beneficios de Usar Swagger

- **Documentación Automática**: Swagger genera automáticamente la documentación de la API basada en los controladores y métodos definidos en el código.
- **Interfaz de Usuario Interactiva**: Proporciona una interfaz de usuario interactiva que permite a los desarrolladores explorar y probar los endpoints de la API.
- **Mejora la Comunicación**: Facilita la comunicación entre los equipos de desarrollo y otros stakeholders al proporcionar una documentación clara y actualizada de la API.
- **Facilita el Desarrollo**: Permite a los desarrolladores probar rápidamente los endpoints de la API sin necesidad de escribir código adicional para las pruebas.

### Actividad Práctica

- **Acceder a la Interfaz de Usuario de Swagger**:
      - Una vez configurado Swagger, inicia la aplicación Spring Boot.
      - Abre un navegador web y navega a `http://localhost:8080/swagger-ui.html`.
      - Explora la interfaz de usuario de Swagger para ver y probar los endpoints de la API.


## Capítulo 5: Documentación con Swagger

### Introducción a Swagger

En este capítulo se aborda la configuración y personalización de Swagger, una herramienta ampliamente utilizada para documentar y probar APIs RESTful en Spring Boot. Swagger proporciona una interfaz de usuario interactiva que facilita la exploración de los endpoints disponibles, mejorando la comunicación entre los equipos de desarrollo y otros stakeholders. A través de este capítulo, se presentarán los conceptos clave, la configuración básica en un proyecto Spring Boot, la personalización avanzada de la documentación y la generación automática de clientes API a partir de la documentación generada.

### Configuración de Swagger en Spring Boot

Para integrar Swagger en una aplicación Spring Boot, es necesario agregar la dependencia correspondiente y configurar las rutas de acceso.

Agregar la dependencia en pom.xml:

```xml
<dependency>
    <groupId>org.springdoc</groupId>
    <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
    <version>2.8.3</version>
</dependency>
```

Configurar las rutas en application.properties:

```properties
springdoc.swagger-ui.path=/swagger-ui.html
springdoc.api-docs.path=/v3/api-docs
```

Definir la configuración en OpenAPIConfig.java (esta configuración no es imprescindible para el funcionamiento):
```java
@Configuration
public class OpenAPIConfig {
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("API de Seguridad")
                .version("1.0.0")
                .description("Documentación de la API de Seguridad")
            );
    }
}
```
Configurar la seguridad en SecurityConfig.java para permitir el acceso:
```java
.authorizeHttpRequests(auth -> auth
                // Permitir acceso a rutas públicas
                .requestMatchers("/public/**").permitAll()
                // Permitir acceso a rutas de autenticación
                .requestMatchers("/auth/**").permitAll()
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**", "/swagger-resources/**", "/swagger-ui.html").permitAll()
                // Requerir autenticación para cualquier otra ruta
                .anyRequest().authenticated()
            )
```

Una vez configurado, la interfaz de usuario de Swagger estará disponible en la ruta: http://localhost:8080/swagger-ui/index.html, donde se podrán visualizar y probar los endpoints disponibles.

### Personalización de la documentación

Swagger permite personalizar la documentación utilizando anotaciones específicas en los controladores. Estas anotaciones permiten describir los endpoints, definir ejemplos de respuestas y proporcionar detalles sobre los parámetros de entrada.

#### Personalización con anotaciones

En la clase UserController, se pueden añadir anotaciones como @Operation y @ApiResponse para documentar de manera detallada cada endpoint:

```java
@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService userService;

    @Operation(summary = "Obtener todos los usuarios", description = "Devuelve la lista de usuarios")
    @ApiResponse(responseCode = "200", description = "Usuarios obtenidos con éxito")
    @GetMapping("/list")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> usuarios = userService.getAllUsers();
        return ResponseEntity.status(HttpStatus.OK).body(usuarios);
    }

    @Operation(summary = "Crear un nuevo usuario", description = "Crea un nuevo usuario en el sistema")
    @ApiResponse(responseCode = "201", description = "Usuario creado con éxito")
    @PostMapping("/create")
    public ResponseEntity<String> createUser(@RequestBody String user) {
        return ResponseEntity.ok("Usuario creado: " + user);
    }
}
```

**Incluir ejemplos en modelos de datos**

Swagger permite añadir ejemplos dentro de los modelos de datos utilizando la anotación @Schema:

```java
@Entity
public class User {

    // Identificador único del usuario
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Schema(description = "ID del usuario", example = "1")
    private Long id;

    // Nombre de usuario
    @Schema(description = "Nombre del usuario", example = "Juan Perez")
    private String userName;
[...]
```

**Descripción de parámetros en los controladores**

Para mejorar la documentación de los parámetros de entrada, se puede utilizar la anotación @Parameter en los métodos del controlador:

```java
public class UserController {

    @Autowired
    private UserService userService;

    /**
     * Endpoint para obtener la lista de todos los usuarios.
     *
     * @return ResponseEntity con la lista de usuarios y el estado HTTP OK.
     */
    @Operation(summary = "Obtener todos los usuarios", description = "Devuelve una lista de usuarios registrados")
    @ApiResponse(responseCode = "200", description = "Usuarios obtenidos con éxito")
    @ApiResponse(responseCode = "404", description = "Usuario no encontrado")
    @GetMapping("/list")
    public ResponseEntity<List<User>> getAllUsers() {
        // Obtener la lista de todos los usuarios
        List<User> usuarios = userService.getAllUsers();
        // Devolver la lista de usuarios con el estado HTTP OK
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(usuarios);
    }

    @Operation(summary = "Crear un nuevo usuario")
    @ApiResponse(responseCode = "201", description = "Usuario creado con éxito")
    @PostMapping("/create")
    public ResponseEntity<String> createUser(@RequestBody String user) {
        return ResponseEntity.ok("Usuario creado: " + user);
    }
}
```

### Beneficios de utilizar Swagger

El uso de Swagger en un proyecto Spring Boot aporta múltiples ventajas, entre las cuales destacan:

- Documentación automática: Se genera a partir de los controladores de la aplicación.
- Interfaz interactiva: Permite probar los endpoints sin necesidad de herramientas adicionales.
- Mejora de la comunicación: Facilita la colaboración entre equipos de desarrollo y otros stakeholders.
- Facilita el desarrollo: Proporciona una forma rápida de probar funcionalidades sin escribir código adicional.


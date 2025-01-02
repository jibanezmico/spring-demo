## Capítulo 2: Introducción a Spring Web

### Introducción

Spring Web es un módulo de Spring que facilita la creación de aplicaciones web y servicios RESTful. Proporciona soporte para controladores, vistas y modelos, y permite manejar solicitudes HTTP de manera sencilla.

### Principales Anotaciones

- **@RestController**: Indica que la clase es un controlador RESTful.
- **@RequestMapping**: Mapea solicitudes HTTP a métodos específicos en un controlador.
- **@GetMapping**: Maneja solicitudes HTTP GET.
- **@PostMapping**: Maneja solicitudes HTTP POST.
- **@PutMapping**: Maneja solicitudes HTTP PUT.
- **@DeleteMapping**: Maneja solicitudes HTTP DELETE.
- **@PathVariable**: Vincula una variable de ruta a un parámetro de método.
- **@RequestParam**: Vincula un parámetro de solicitud a un parámetro de método.
- **@RequestBody**: Vincula el cuerpo de una solicitud a un parámetro de método.

### Ejemplos de Anotaciones

```java
@RestController
@RequestMapping("/api")
public class ExampleController {
    private static final Logger logger = LoggerFactory.getLogger(ExampleController.class);

    @GetMapping("/hello")
    public String sayHello() {
        logger.info("sayHello endpoint llamado");
        return "Hello, World!";
    }

    @RequestMapping(value = "/greet", method = RequestMethod.GET)
    public String greet() {
        logger.info("greet endpoint llamado");
        return "Greetings!";
    }

    @PostMapping("/create")
    public String create(@RequestBody String data) {
        logger.info("create endpoint llamado con datos: {}", data);
        return "Data created: " + data;
    }

    @PutMapping("/update")
    public String update(@RequestBody String data) {
        logger.info("update endpoint llamado con datos: {}", data);
        return "Data updated: " + data;
    }

    @DeleteMapping("/delete/{id}")
    public String delete(@PathVariable Long id) {
        logger.info("delete endpoint llamado con id: {}", id);
        return "Data deleted with id: " + id;
    }

    @GetMapping("/user/{id}")
    public String getUser(@PathVariable Long id) {
        logger.info("getUser endpoint llamado con id: {}", id);
        return "User ID: " + id;
    }

    @GetMapping("/search")
    public String search(@RequestParam String query) {
        logger.info("search endpoint llamado con query: {}", query);
        return "Search query: " + query;
    }

    @PostMapping("/add")
    public String add(@RequestBody String data) {
        logger.info("add endpoint llamado con datos: {}", data);
        return "Data added: " + data;
    }
}
```

### Explicación del Código

- `@RestController`: Indica que la clase es un controlador RESTful.
- `@RequestMapping`: Mapea solicitudes HTTP a métodos específicos en un controlador.
- `@GetMapping`: Maneja solicitudes HTTP GET.
- `@PostMapping`: Maneja solicitudes HTTP POST.
- `@PutMapping`: Maneja solicitudes HTTP PUT.
- `@DeleteMapping`: Maneja solicitudes HTTP DELETE.
- `@PathVariable`: Vincula una variable de ruta a un parámetro de método.
- `@RequestParam`: Vincula un parámetro de solicitud a un parámetro de método.
- `@RequestBody`: Vincula el cuerpo de una solicitud a un parámetro de método.
- `Logger`: Utilizado para registrar eventos importantes y errores en la aplicación.

### Actividad Práctica

1. **Crear un servicio REST "Hola Mundo"**:
   - Crear un controlador RESTful que maneje una solicitud GET y devuelva un mensaje "Hola Mundo".

   ```java
   @RestController
   @RequestMapping("/api")
   public class HolaMundoController {
       private static final Logger logger = LoggerFactory.getLogger(HolaMundoController.class);

       @GetMapping("/hola")
       public String holaMundo() {
           logger.info("holaMundo endpoint llamado");
           return "Hola Mundo";
       }
   }
   ```

### Ejemplo Práctico

1. **Crear un controlador RESTful que maneje una solicitud POST con parámetros y cuerpo**:
   - Crear un controlador RESTful que maneje una solicitud POST, reciba parámetros en la URL y un cuerpo en la solicitud.

   ```java
   @RestController
   @RequestMapping("/api")
   public class ComplexController {
       private static final Logger logger = LoggerFactory.getLogger(ComplexController.class);

       @PostMapping("/process")
       public ResponseEntity<String> processRequest(
               @RequestParam String param,
               @RequestBody Map<String, Object> body) {
           logger.info("processRequest endpoint llamado con param: {} y body: {}", param, body);
           String response = "Received param: " + param + " and body: " + body.toString();
           return ResponseEntity.ok(response);
       }
   }
   ```

### Explicación del Código

- `@RestController`: Indica que la clase es un controlador RESTful.
- `@RequestMapping("/api")`: Mapea las solicitudes HTTP a la ruta base `/api`.
- `@PostMapping("/process")`: Maneja las solicitudes HTTP POST a la ruta `/api/process`.
- `@RequestParam String param`: Vincula un parámetro de solicitud a un parámetro de método.
- `@RequestBody Map<String, Object> body`: Vincula el cuerpo de una solicitud a un parámetro de método.
- `ResponseEntity<String>`: Representa la respuesta HTTP con un cuerpo de tipo `String`.
- `Logger`: Utilizado para registrar eventos importantes y errores en la aplicación.

### Actividad Práctica

1. **Probar el Controlador RESTful**:
   - Iniciar la aplicación Spring Boot.
   - Utilizar una herramienta como Postman para enviar una solicitud POST a `http://localhost:8080/api/process` con un parámetro `param` y un cuerpo JSON.
   - Verificar que la respuesta incluya tanto el parámetro como el cuerpo de la solicitud.

### Beneficios de Usar Spring Web

- **Facilidad de Uso**: Spring Web proporciona anotaciones que simplifican la creación de controladores y el manejo de solicitudes HTTP.
- **Flexibilidad**: Permite manejar diferentes tipos de solicitudes HTTP (GET, POST, PUT, DELETE) y vincular parámetros de solicitud y variables de ruta a métodos de controlador.
- **Integración con Spring Boot**: Se integra fácilmente con aplicaciones Spring Boot, lo que facilita su configuración y uso.

### Actividad Práctica

1. **Probar el Servicio REST "Hola Mundo"**:
   - Iniciar la aplicación Spring Boot.
   - Utilizar un navegador web o una herramienta como Postman para enviar una solicitud GET a `http://localhost:8080/api/hola`.
   - Verificar que la respuesta sea "Hola Mundo".

### Validaciones en Spring Boot

#### Introducción a las Validaciones en Spring Boot

Spring Boot proporciona soporte para validaciones utilizando la especificación Bean Validation (JSR 380). Esto permite validar datos de entrada en controladores, servicios y entidades de manera sencilla y declarativa.

#### Configuración de Dependencias

Para utilizar las validaciones en Spring Boot, es necesario añadir la dependencia `spring-boot-starter-validation` en el archivo `pom.xml`:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>
```

#### Validaciones en Entidades

Las validaciones se pueden aplicar a las entidades utilizando anotaciones como `@NotNull`, `@Size`, `@Email`, entre otras. Aquí hay un ejemplo de cómo aplicar validaciones a una entidad `User`:

```java
@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @NotNull(message = "El nombre de usuario no puede ser nulo")
    @Size(min = 3, max = 50, message = "El nombre de usuario debe tener entre 3 y 50 caracteres")
    private String userName;

    @NotNull(message = "La contraseña no puede ser nula")
    @Size(min = 6, message = "La contraseña debe tener al menos 6 caracteres")
    private String password;

    @NotNull(message = "El rol no puede ser nulo")
    private String role;

    // Getters y setters...
}
```

#### Validaciones en Controladores

Las validaciones se pueden aplicar a los datos de entrada en los controladores utilizando la anotación `@Valid`. Aquí hay un ejemplo de cómo validar un objeto `User` en un controlador:

```java
@RestController
@RequestMapping("/api/users")
public class UserController {
    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    @Autowired
    private UserService userService;

    @PostMapping
    public ResponseEntity<User> createUser(@Valid @RequestBody User user, BindingResult result) {
        logger.info("createUser endpoint llamado con datos: {}", user);
        if (result.hasErrors()) {
            logger.error("Errores de validación: {}", result.getAllErrors());
            return ResponseEntity.badRequest().body(null);
        }
        User savedUser = userService.saveUser(user);
        return ResponseEntity.ok(savedUser);
    }
}
```

#### Validaciones en Servicios

Las validaciones también se pueden aplicar en los servicios utilizando la anotación `@Validated`. Aquí hay un ejemplo de cómo validar un objeto `User` en un servicio:

```java
@Service
@Validated
public class UserService {
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    @Autowired
    private UserRepository userRepository;

    public User saveUser(@Valid User user) {
        logger.info("Guardando usuario: {}", user.getUserName());
        return userRepository.save(user);
    }
}
```

#### Explicación del Código

- `@NotNull`, `@Size`, `@Email`: Anotaciones de validación que se utilizan para validar los campos de una entidad.
- `@Valid`: Anotación que se utiliza para validar un objeto en un controlador o servicio.
- `BindingResult`: Objeto que contiene los resultados de la validación.
- `@Validated`: Anotación que se utiliza para habilitar la validación en un servicio.
- `Logger`: Utilizado para registrar eventos importantes y errores en la aplicación.

#### Beneficios de Usar Validaciones en Spring Boot

- **Simplicidad**: Las validaciones se pueden aplicar de manera declarativa utilizando anotaciones.
- **Reutilización**: Las reglas de validación se pueden reutilizar en diferentes capas de la aplicación.
- **Consistencia**: Las validaciones aseguran que los datos de entrada cumplan con las reglas definidas, mejorando la consistencia de los datos.

#### Actividad Práctica

1. **Aplicar Validaciones a una Entidad**:
   - Añadir anotaciones de validación a la entidad `User`.
   - Crear un controlador y un servicio que utilicen las validaciones.
   - Probar las validaciones utilizando una herramienta como Postman.

### Posibles Errores Comunes

1. **Errores de Validación**:
   - **Solución**: Verificar que los datos de entrada cumplen con las reglas de validación definidas en las anotaciones.

2. **Dependencias**:
   - **Solución**: Asegurarse de que la dependencia `spring-boot-starter-validation` esté incluida en el archivo `pom.xml` y ejecutar `mvn clean install` para actualizar el proyecto.

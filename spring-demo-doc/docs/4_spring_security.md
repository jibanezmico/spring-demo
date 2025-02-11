# Configuración de Seguridad en Spring Security

En esta sección se describe la configuración de seguridad de la aplicación mediante Spring Security, incluyendo la gestión de autenticación y autorización basada en tokens JWT.

Para ello debemos añadir en nuestro pom.xml las siguientes dependencias, que son esenciales para la implementación de seguridad en la aplicación:

```xml
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt</artifactId>
			<version>0.9.1</version>
		</dependency>
```

En determinadas versiones de jjwt (como la 0.9.1), la biblioteca depende de `javax.xml.bind.DatatypeConverter`, una clase que formaba parte de JAXB y que fue eliminada a partir de Java 11. Esto provoca errores como `NoClassDefFoundError` o `ClassNotFoundException` cuando se ejecuta la aplicación en un entorno con JDK 11 o superior.

Para evitar estos errores y garantizar la compatibilidad con esta versión de jjwt, es necesario incluir explícitamente la dependencia de JAXB en el pom.xml::

```xml
        <dependency>
			<groupId>javax.xml.bind</groupId>
			<artifactId>jaxb-api</artifactId>
			<version>2.3.1</version>
		</dependency>
		<dependency>
			<groupId>org.glassfish.jaxb</groupId>
			<artifactId>jaxb-runtime</artifactId>
		</dependency>
```

La dependencia `spring-boot-starter-security` proporciona la integración de Spring Security, facilitando la gestión de autenticación y autorización mediante configuraciones predeterminadas que incluyen la protección contra ataques comunes como CSRF y XSS. Esta dependencia permite la implementación de autenticación basada en sesiones, roles y personalización de accesos.

Por otro lado, la dependencia `jjwt` (Java JWT) permite la generación, firma y validación de tokens JWT en la aplicación. Con ella, es posible crear tokens seguros mediante algoritmos de cifrado como HS256, además de extraer información del token, como el nombre de usuario o la fecha de expiración, para su validación y uso dentro del sistema.

## Configuración de Spring Security

La clase `SecurityConfig` configura la seguridad de la aplicación utilizando Spring Security, estableciendo reglas de autenticación y autorización para proteger los recursos. Mediante la anotación `@Configuration`, esta clase es detectada por el contexto de Spring para aplicar la configuración de seguridad. La anotación `@EnableWebSecurity` permite a Spring configurar la seguridad web en la aplicación.

El método `securityFilterChain` configura la seguridad HTTP mediante el objeto `HttpSecurity`. En primer lugar, se deshabilita CSRF para simplificar la autenticación mediante tokens JWT, ya que no se requiere protección contra ataques de falsificación de solicitudes en aplicaciones sin estado. Se establecen reglas de autorización, permitiendo el acceso sin autenticación a las rutas públicas `/public/**` y `/auth/**`, mientras que cualquier otra ruta requiere autenticación. Además, se gestiona el control de errores mediante `JwtEntryPoint`, que proporciona respuestas adecuadas en caso de intentos de acceso no autorizados.

Para la autenticación, se añade el filtro `JwtAuthenticationFilter`, que intercepta las solicitudes antes de que sean procesadas por el filtro de autenticación estándar de Spring Security. Este filtro valida los tokens JWT presentes en las solicitudes HTTP, extrayendo el usuario autenticado y sus roles para establecer la autenticación en el contexto de seguridad.

El método `authenticationManager` proporciona una instancia de `AuthenticationManager`, que se encarga de autenticar las credenciales del usuario utilizando los servicios de usuario configurados en la aplicación. Por último, el método `passwordEncoder` define un codificador de contraseñas basado en BCrypt, que garantiza el almacenamiento seguro de contraseñas mediante un algoritmo de hashing robusto.

Esta configuración ofrece una solución de seguridad flexible y segura basada en Spring Security, asegurando la correcta gestión de autenticación y autorización en la aplicación, con protección adecuada de los recursos sensibles.

```java
/**
 * Clase de configuración de seguridad. Se definen las reglas de seguridad.
 * SecurityConfig
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // Inyección de dependencias para manejar errores de autenticación
    @Autowired
    private JwtEntryPoint jwtEntryPoint;

    // Definición del filtro de autenticación JWT como un bean
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }

    /**
     * Configuración de la cadena de filtros de seguridad.
     *
     * @param http Objeto HttpSecurity para configurar la seguridad HTTP.
     * @return SecurityFilterChain configurado.
     * @throws Exception en caso de error en la configuración de seguridad.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Desactivar CSRF para simplificar la configuración
            .csrf(csrf -> csrf.disable())
            // Configuración de las reglas de autorización
            .authorizeHttpRequests(auth -> auth
                // Permitir acceso a rutas públicas
                .requestMatchers("/public/**").permitAll()
                // Permitir acceso a rutas de autenticación
                .requestMatchers("/auth/**").permitAll()
                // Requerir autenticación para cualquier otra ruta
                .anyRequest().authenticated()
            )
            // Manejar errores de autenticación con JwtEntryPoint
            .exceptionHandling(exception -> exception
                .authenticationEntryPoint(jwtEntryPoint)
            )
            // Añadir el filtro de autenticación JWT antes del filtro de autenticación de usuario y contraseña
            .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
            // Configuración de la página de inicio de sesión personalizada (opcional)
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            );
        return http.build();
    }

    /**
     * Definición del bean AuthenticationManager para manejar la autenticación.
     *
     * @param authenticationConfiguration Objeto AuthenticationConfiguration para configurar el AuthenticationManager.
     * @return AuthenticationManager configurado.
     * @throws Exception en caso de error en la configuración del AuthenticationManager.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * Definición del bean PasswordEncoder para codificar las contraseñas.
     *
     * @return PasswordEncoder configurado.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

## JwtAuthenticationFilter

La clase `JwtAuthenticationFilter` es un filtro personalizado en Spring Security que intercepta cada solicitud HTTP entrante para autenticar al usuario utilizando un token JWT. Extiende `OncePerRequestFilter`, lo que garantiza que el filtro se ejecute solo una vez por solicitud.

El método principal doFilterInternal se encarga de extraer el token JWT de la cabecera de autorización de la solicitud mediante el método privado `getJwtFromRequest`. Si se encuentra un token válido, se utiliza la clase `JwtProvider` para validarlo y extraer el nombre de usuario. Luego, se cargan los detalles del usuario desde la base de datos utilizando `UserDetailsService`, lo que permite crear un objeto de autenticación con sus roles y establecerlo en el contexto de seguridad de Spring Security.

Este filtro es crucial para el control de acceso en la aplicación, ya que verifica la autenticidad del token y permite a los usuarios acceder a recursos protegidos si la autenticación es exitosa. La clase se configura en `SecurityConfig` utilizando el método `addFilterBefore`, asegurando que se ejecute antes del filtro de autenticación estándar de Spring.

```java
/**
 * Filtro de autenticación JWT que se ejecuta una vez por solicitud.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtProvider jwtProvider;
    @Autowired
    private UserDetailsService userDetailsService;

    /**
     * Método que filtra cada solicitud para autenticar el usuario basado en el token JWT.
     *
     * @param request     El objeto HttpServletRequest.
     * @param response    El objeto HttpServletResponse.
     * @param filterChain La cadena de filtros.
     * @throws ServletException en caso de error en el servlet.
     * @throws IOException      en caso de error de E/S.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Obtener el token JWT de la solicitud
        String jwt = getJwtFromRequest(request);

        // Validar el token JWT
        if (jwt != null && jwtProvider.validateToken(jwt)) {
            // Obtener el nombre de usuario del token JWT
            String username = jwtProvider.extractUsername(jwt);

            // Cargar los detalles del usuario
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // Crear la autenticación basada en el token JWT
            if (userDetails != null) {
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Establecer la autenticación en el contexto de seguridad
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        // Continuar con la cadena de filtros
        filterChain.doFilter(request, response);
    }

    /**
     * Obtiene el token JWT de la solicitud.
     *
     * @param request El objeto HttpServletRequest.
     * @return El token JWT si está presente, de lo contrario null.
     */
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
```


## Punto de Entrada de Autenticación

La clase `JwtEntryPoint` actúa como un punto de entrada de autenticación para Spring Security y se encarga de gestionar los errores de autenticación cuando una solicitud no autenticada intenta acceder a recursos protegidos de la aplicación. Implementa la interfaz `AuthenticationEntryPoint`, lo que permite interceptar las solicitudes no autorizadas y devolver respuestas adecuadas al cliente.

Cuando se produce un error de autenticación, el método commence se ejecuta automáticamente. Dentro de este método, se extrae la URL de la solicitud y la dirección IP del cliente para registrar los intentos fallidos de acceso. Dependiendo del tipo de excepción de autenticación detectada, la aplicación devuelve un mensaje de error personalizado, como “Credenciales erróneas” para errores de autenticación por credenciales incorrectas, o “No autorizado” para intentos de acceso sin credenciales.

Este componente es fundamental para garantizar la seguridad de la aplicación, ya que permite responder de manera adecuada a intentos de acceso no autorizados, registrando información útil para auditoría y monitoreo de seguridad. La clase `JwtEntryPoint` se configura en la clase `SecurityConfig` dentro del método de configuración de excepciones, asegurando que todas las solicitudes que requieran autenticación sean gestionadas correctamente.

```java
/**
 * Punto de entrada de autenticación JWT que se ejecuta cuando se produce un error de autenticación.
 */
@Component
public class JwtEntryPoint implements AuthenticationEntryPoint {

    /**
     * Método que se ejecuta cuando se produce un error de autenticación.
     *
     * @param request       El objeto HttpServletRequest.
     * @param response      El objeto HttpServletResponse.
     * @param authException La excepción de autenticación.
     * @throws IOException      en caso de error de E/S.
     * @throws ServletException en caso de error en el servlet.
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        // Obtener la URL completa de la solicitud
        String urlRequest = SecurityUtils.getFullURL(request);
        // Obtener la IP del cliente
        String ip = SecurityUtils.getClientIP(request);

        // Manejar diferentes tipos de excepciones de autenticación
        if (authException instanceof BadCredentialsException || authException instanceof InternalAuthenticationServiceException) {
            // El token no es válido. Puede añadirse un control para bloquear la IP.
            System.err.println("Error de autenticación. IP: " + ip + ". Request URL: " + urlRequest);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Credenciales erróneas");
        } else {
            // No autorizado
            System.err.println("Error de petición. IP: " + ip + ". Request URL: " + urlRequest);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "No autorizado");
        }
    }
}
```

## Proveedor de Tokens JWT

La clase `JwtProvider` es responsable de la generación y validación de tokens JWT en la aplicación. Su principal función es proporcionar métodos seguros para la creación, extracción y verificación de información contenida en los tokens JWT, permitiendo así la autenticación y autorización de usuarios en las solicitudes HTTP.

Para generar un token JWT, el método `generateToken` recibe un objeto de autenticación y crea un token firmado con una clave secreta almacenada en la configuración de la aplicación. Este token incluye el nombre de usuario como sujeto, la fecha de emisión y una fecha de expiración definida en segundos.

La clase también proporciona métodos para extraer información del token, como el nombre de usuario y la fecha de expiración, utilizando la función `extractClaim`, que permite obtener diferentes atributos del token. Además, el método `validateToken` verifica la validez del token, comprobando su estructura, firma, y si ha expirado o no.

En caso de errores durante la validación, como tokens mal formados, expirados o vacíos, se registran mensajes de error en la salida estándar para facilitar la depuración.

Esta clase es utilizada en otras partes de la aplicación, como el controlador de autenticación (`AuthController`), donde se emplea para generar tokens JWT tras un inicio de sesión exitoso. También se integra con los filtros de seguridad para validar tokens en cada solicitud y asegurar que solo usuarios autenticados puedan acceder a recursos protegidos.

```java
/**
 * Proveedor de JWT que maneja la generación y validación de tokens JWT.
 */
@Component
public class JwtProvider {

    // Clave secreta para firmar el token JWT
    @Value("${jwt.secret}")
    private String secret;
    @Value("${jwt.expiration}")
    private int expiration;

    /**
     * Genera un token JWT basado en la autenticación.
     *
     * @param authentication La autenticación del usuario.
     * @return El token JWT generado.
     */
    public String generateToken(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration * 1000)) // 10 horas de expiración
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();
    }

    /**
     * Extrae el nombre de usuario del token JWT.
     *
     * @param token El token JWT.
     * @return El nombre de usuario extraído del token.
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extrae la fecha de expiración del token JWT.
     *
     * @param token El token JWT.
     * @return La fecha de expiración del token.
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extrae un reclamo específico del token JWT.
     *
     * @param token El token JWT.
     * @param claimsResolver La función para resolver el reclamo.
     * @param <T> El tipo del reclamo.
     * @return El reclamo extraído.
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extrae todos los reclamos del token JWT.
     *
     * @param token El token JWT.
     * @return Los reclamos extraídos del token.
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    /**
     * Verifica si el token JWT ha expirado.
     *
     * @param token El token JWT.
     * @return true si el token ha expirado, false en caso contrario.
     */
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Valida el token JWT.
     *
     * @param token El token JWT.
     * @return true si el token es válido, false en caso contrario.
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(secret).parseClaimsJws(token);
            return true;
        } catch (MalformedJwtException e) {
            System.err.println("token mal formado");
        } catch (UnsupportedJwtException e) {
            System.err.println("token no soportado");
        } catch (ExpiredJwtException e) {
            System.err.println("token expirado");
        } catch (IllegalArgumentException e) {
            System.err.println("token vacío");
        }
        return false;
    }

    /**
     * Valida el token JWT contra los detalles del usuario.
     *
     * @param token El token JWT.
     * @param userDetails Los detalles del usuario.
     * @return true si el token es válido y coincide con los detalles del usuario, false en caso contrario.
     */
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
```

Las propiedades inyectadas con `@Value` deben introducirse en el fichero properties:

```proprties
jwt.secret=secret
jwt.expiration=36000
```

## Controlador de Usuarios

La clase `UserController` es responsable de manejar las solicitudes relacionadas con la gestión de usuarios dentro de la aplicación. Proporciona un endpoint para recuperar la lista completa de usuarios registrados en el sistema.

El método `getAllUsers()` expuesto mediante la anotación `@GetMapping("/list")` permite obtener todos los usuarios almacenados en la base de datos. Este método utiliza el servicio `UserService` para obtener la lista de usuarios y devuelve la información dentro de un objeto `ResponseEntity`, con un código de estado `HTTP 200 (OK)` en caso de éxito.

Al utilizar la anotación `@RestController`, el controlador se encarga de gestionar las solicitudes HTTP entrantes y devolver respuestas en formato JSON. La inyección de dependencias mediante `@Autowired` permite acceder a los métodos del servicio de usuarios de forma sencilla, delegando la lógica de negocio a la capa de servicio.

```java
/**
 * Controlador que maneja las solicitudes relacionadas con los usuarios.
 */
@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService userService;

    /**
     * Endpoint para obtener la lista de todos los usuarios.
     *
     * @return ResponseEntity con la lista de usuarios y el estado HTTP OK.
     */
    @GetMapping("/list")
    public ResponseEntity<List<User>> getAllUsers() {
        // Obtener la lista de todos los usuarios
        List<User> usuarios = userService.getAllUsers();
        // Devolver la lista de usuarios con el estado HTTP OK
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(usuarios);
    }
}
```


## Controlador de autenticación

La clase `AuthController` es responsable de gestionar la autenticación de usuarios mediante `JWT (JSON Web Token)`. Su propósito principal es proporcionar un punto de entrada para el inicio de sesión, lo que permite a los usuarios autenticarse y recibir un token JWT para acceder a recursos protegidos en la aplicación.

El controlador recibe las credenciales del usuario a través de un objeto `LoginUsuario`, que contiene el nombre de usuario y la contraseña. Primero, verifica la existencia del usuario en la base de datos utilizando `UserService`. Si el usuario no se encuentra, devuelve un mensaje de error indicando credenciales incorrectas. Si el usuario existe, el controlador intenta autenticarlo utilizando el `AuthenticationManager`. Si la autenticación es exitosa, se genera un token JWT mediante `JwtProvider` y se devuelve encapsulado en un objeto `JwtDto`, que contiene el token, el nombre de usuario y sus roles asociados.

Durante el proceso, se registran la IP del cliente y la URL de la solicitud utilizando `SecurityUtils` para propósitos de auditoría y trazabilidad. Si la autenticación falla, se devuelve un mensaje de error con el estado `HTTP 400 (Bad Request)`. Por otro lado, si el inicio de sesión es exitoso, se devuelve una respuesta `HTTP 200` con el token generado, que posteriormente se utilizará en las solicitudes a endpoints protegidos enviándolo en la cabecera `Authorization: Bearer <token>`.

```java
/**
 * Controlador de autenticación que maneja las solicitudes de inicio de sesión y generación de JWT.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    // Inyección de dependencias para manejar la autenticación
    @Autowired
    private AuthenticationManager authenticationManager;

    // Inyección de dependencias para manejar la generación de JWT
    @Autowired
    private JwtProvider jwtProvider;

    // Inyección de dependencias para manejar los servicios de usuario
    @Autowired
    private UserService userService;

    /**
     * Endpoint para el login.
     *
     * @param loginUsuario Objeto que contiene el nombre de usuario y la contraseña.
     * @param request      Objeto HttpServletRequest para obtener información de la solicitud.
     * @return ResponseEntity con el JWT y los detalles del usuario, o un mensaje de error.
     */
    @PostMapping("/login")
    public ResponseEntity<RespuestaDto> login(@RequestBody LoginUsuario loginUsuario, HttpServletRequest request){

        // Obtener la IP del cliente y la URL de la solicitud
        String ip = SecurityUtils.getClientIP(request);
        String urlRequest = SecurityUtils.getFullURL(request);

        // Buscar el usuario por nombre de usuario
        Optional<User> optUser = userService.getByUserName(loginUsuario.getNombreUsuario());

        // Si el usuario no existe, devolver un error
        if(optUser.isEmpty()) {
            System.err.println("Error de autenticación. IP: " + ip + ". Request URL: " + urlRequest);
            return new ResponseEntity<>(new Mensaje("Usuario o password incorrectos."), HttpStatus.BAD_REQUEST);
        }
        
		// Autenticar al usuario
		Authentication authentication = authenticationManager.authenticate(
			new UsernamePasswordAuthenticationToken(loginUsuario.getNombreUsuario(), loginUsuario.getPassword())
		);

		// Establecer la autenticación en el contexto de seguridad
		SecurityContextHolder.getContext().setAuthentication(authentication);

		// Generar el token JWT
		String jwt = jwtProvider.generateToken(authentication);
		UserDetails userDetails = (UserDetails) authentication.getPrincipal();

		// Crear el DTO del JWT
		JwtDto jwtDto = new JwtDto(jwt, userDetails.getUsername(), userDetails.getAuthorities());

		// Devolver la respuesta con el JWT
		return new ResponseEntity<>(jwtDto, HttpStatus.OK);
        
    }
}
```

## Servicio publico para pruebas

La clase `PublicController` es un controlador de Spring que expone endpoints accesibles sin necesidad de autenticación, como se indica en la anotación `@RequestMapping("/public")`. Su objetivo principal es proporcionar funcionalidades abiertas que no requieren protección mediante Spring Security.

El controlador inyecta dos dependencias clave: `UserService`, que gestiona la lógica de negocio relacionada con los usuarios, y `PasswordEncoder`, utilizado para codificar contraseñas de manera segura antes de almacenarlas en la base de datos.

Proporciona dos endpoints:
1.	GET /public/list:
	- Este endpoint devuelve una lista de todos los usuarios almacenados en la base de datos.
	- Llama al método getAllUsers() de UserService para obtener la lista de usuarios.
	- Retorna la lista con un estado HTTP 200 (OK).
2.	GET /public/newrandomuser:
	- Permite crear un usuario con un nombre aleatorio y una contraseña predeterminada codificada.
	- Se utiliza el servicio UserService para guardar el usuario en la base de datos.
	- Este endpoint es útil para propósitos de prueba, permitiendo la creación rápida de usuarios cuando se inicia la aplicación.
	- Después de guardar el usuario, devuelve la lista actualizada de usuarios con un estado HTTP 200 (OK).

Este controlador es especialmente útil para probar la funcionalidad del sistema sin necesidad de autenticarse, facilitando la validación de la persistencia de datos y la verificación del servicio de usuarios.

```java
/**
 * Controlador público que maneja las solicitudes accesibles sin autenticación.
 */
@RestController
@RequestMapping("/public")
public class PublicController {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Endpoint para obtener la lista de todos los usuarios.
     *
     * @return ResponseEntity con la lista de usuarios y el estado HTTP OK.
     */
    @GetMapping("/list")
    public ResponseEntity<List<User>> getAllUsers() {
        // Obtener la lista de todos los usuarios
        List<User> usuarios = userService.getAllUsers();
        // Devolver la lista de usuarios con el estado HTTP OK
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(usuarios);
    }

    /**
     * Endpoint para crear un nuevo usuario aleatorio y devolver la lista actualizada de usuarios.
     * Este método es solo para pruebas y nos permite crear usuarios si no tenemos ninguno al iniciar
     * la aplicación por primera vez
     *
     * @return ResponseEntity con la lista actualizada de usuarios y el estado HTTP OK.
     */
    @GetMapping("/newrandomuser")
    public ResponseEntity<List<User>> newRandomUser() {
        // Crear un nuevo usuario con un nombre de usuario aleatorio y una contraseña codificada
        User user = new User();
        user.setUserName("user" + (int)(Math.random() * 1000));
        user.setPassword(passwordEncoder.encode("password"));
        user.setRole("USER");

        // Guardar el nuevo usuario en la base de datos
        userService.saveUser(user);

        // Obtener la lista actualizada de todos los usuarios
        List<User> usuarios = userService.getAllUsers();
        // Devolver la lista actualizada de usuarios con el estado HTTP OK
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(usuarios);
    }
}
```

## Servicio de Usuarios

La clase `UserService` es un servicio de Spring que gestiona las operaciones relacionadas con los usuarios. Implementa la interfaz `UserDetailsService` de Spring Security para cargar detalles de usuario durante la autenticación.

El método `loadUserByUsername(String username)` se encarga de buscar un usuario en la base de datos mediante el repositorio `UserRepository`. Si el usuario no se encuentra, lanza una excepción `UsernameNotFoundException`. Si el usuario existe, se devuelve una instancia de `UserDetails` que contiene el nombre de usuario, la contraseña y el rol del usuario, el cual se asigna como una autoridad de seguridad en formato `ROLE_`.

Además, la clase proporciona métodos adicionales como `getAllUsers()`, que devuelve una lista con todos los usuarios almacenados en la base de datos; `saveUser(User user)`, que guarda un usuario nuevo o actualiza uno existente; y `getByUserName(String userName)`, que retorna un usuario específico encapsulado en un objeto `Optional`.

Esta clase es utilizada en controladores como `AuthController` para autenticar usuarios y proporcionar la información de autenticación necesaria para la gestión de accesos en la aplicación.

```java
/**
 * Servicio para manejar las operaciones relacionadas con los usuarios.
 */
@Service
public class UserService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    /**
     * Carga un usuario por su nombre de usuario.
     *
     * @param username El nombre de usuario.
     * @return Los detalles del usuario.
     * @throws UsernameNotFoundException si el usuario no se encuentra.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Buscar el usuario por nombre de usuario en el repositorio
        User user = userRepository.findByUserName(username)
            .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

        // Crear y devolver un objeto UserDetails con el nombre de usuario, contraseña y rol del usuario
        return new org.springframework.security.core.userdetails.User(
            user.getUserName(),
            user.getPassword(),
            Collections.singleton(new SimpleGrantedAuthority("ROLE_" + user.getRole()))
        );
    }

    /**
     * Obtiene todos los usuarios.
     *
     * @return Una lista de todos los usuarios.
     */
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    /**
     * Guarda un usuario.
     *
     * @param user El usuario a guardar.
     * @return El usuario guardado.
     */
    public User saveUser(User user) {
        return userRepository.save(user);
    }

    /**
     * Obtiene un usuario por su nombre de usuario.
     *
     * @param userName El nombre de usuario.
     * @return Un Optional que contiene el usuario encontrado, o vacío si no se encuentra.
     */
    public Optional<User> getByUserName(String userName) {
        return userRepository.findByUserName(userName);
    }
}
```

## Repositorio de Usuarios

La interfaz `UserRepository` extiende `JpaRepository` y proporciona métodos de acceso a la base de datos para la entidad `User`, permitiendo realizar operaciones CRUD de manera sencilla y eficiente gracias a la integración con Spring Data JPA. Además de los métodos heredados de `JpaRepository`, define dos métodos personalizados: `findById(long id)`, que permite recuperar un usuario a partir de su identificador único, y `findByUserName(String userName)`, que devuelve un objeto `Optional<User>` basado en el nombre de usuario, lo que facilita la gestión de casos en los que el usuario no exista. Esta interfaz es utilizada en la capa de servicio, concretamente en `UserService`, donde se encapsulan las reglas de negocio relacionadas con la gestión de usuarios y se proporcionan a los controladores para manejar las peticiones HTTP.

```java
/**
 * Repositorio para la entidad User.
 * 
 * Proporciona métodos para realizar operaciones CRUD en la entidad User.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Encuentra un usuario por su identificador.
     *
     * @param id El identificador del usuario.
     * @return El usuario encontrado.
     */
    public User findById(long id);

    /**
     * Encuentra un usuario por su nombre de usuario.
     *
     * @param userName El nombre de usuario.
     * @return Un Optional que contiene el usuario encontrado, o vacío si no se encuentra.
     */
    public Optional<User> findByUserName(String userName);

}
```

## Entidad User

La clase `User` representa la entidad de usuario en la base de datos, almacenando información esencial como el identificador único, el nombre de usuario, la contraseña y el rol asignado. Esta entidad se utiliza en distintas capas de la aplicación, como en el repositorio `UserRepository` para realizar operaciones de persistencia, y en el servicio `UserService` donde se gestionan las interacciones con los datos de usuario. Además, es fundamental en el proceso de autenticación y autorización, ya que Spring Security utiliza esta clase para validar credenciales y asignar roles a los usuarios autenticados. La propiedad `role` permite implementar políticas de control de acceso según los permisos de cada usuario.

```java
/**
 * Entidad que representa un usuario en la base de datos.
 */
@Entity
public class User {

    // Identificador único del usuario
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    // Nombre de usuario
    private String userName;

    // Contraseña del usuario
    private String password;

    // Rol del usuario
    private String role;

    /**
     * Obtiene el identificador único del usuario.
     *
     * @return El identificador único del usuario.
     */
    public Long getId() {
        return id;
    }

    /**
     * Establece el identificador único del usuario.
     *
     * @param id El identificador único del usuario.
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * Obtiene el nombre de usuario.
     *
     * @return El nombre de usuario.
     */
    public String getUserName() {
        return userName;
    }

    /**
     * Establece el nombre de usuario.
     *
     * @param userName El nombre de usuario.
     */
    public void setUserName(String userName) {
        this.userName = userName;
    }

    /**
     * Obtiene la contraseña del usuario.
     *
     * @return La contraseña del usuario.
     */
    public String getPassword() {
        return password;
    }

    /**
     * Establece la contraseña del usuario.
     *
     * @param password La contraseña del usuario.
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * Obtiene el rol del usuario.
     *
     * @return El rol del usuario.
     */
    public String getRole() {
        return role;
    }

    /**
     * Establece el rol del usuario.
     *
     * @param role El rol del usuario.
     */
    public void setRole(String role) {
        this.role = role;
    }
}
```

## Interfaz para las respuestas DTO.

La interfaz `RespuestaDto` se utiliza en clases como `AuthController` para permitir que los métodos de autenticación encapsulen distintos tipos de respuesta bajo una misma estructura. Esto proporciona flexibilidad a la hora de devolver datos al cliente, ya que se pueden enviar tanto un token de autenticación mediante la clase `JwtDto` como mensajes de error o confirmación a través de la clase `Mensaje`. Gracias a esta implementación, el controlador puede gestionar de forma homogénea las respuestas, facilitando su manipulación en el frontend y asegurando una comunicación clara y estructurada entre las capas de la aplicación.

```java
/**
 * Interfaz de marcador para los DTOs de respuesta.
 * 
 * Esta interfaz no define métodos, pero se utiliza para marcar las clases que
 * representan respuestas en la aplicación.
 */
public interface RespuestaDto {
    // Interfaz de marcador sin métodos
}
```

## DTO para el token JWT.

La clase `JwtDto` es un objeto de transferencia de datos (DTO) que encapsula la información relevante de un token JWT, proporcionando el token de acceso, el tipo de token (Bearer), el nombre de usuario autenticado y las autoridades o roles asociados. Su principal finalidad es facilitar el envío de estos datos desde el backend hacia el cliente tras un proceso de autenticación exitoso, permitiendo que el cliente utilice el token en futuras solicitudes para acceder a recursos protegidos. Este DTO garantiza una gestión estructurada de la autenticación, asegurando que la información del usuario se transmita de manera segura y organizada en la aplicación.

```java
/**
 * DTO para el token JWT.
 */
public class JwtDto implements RespuestaDto {
    private String token;
    private String bearer = "Bearer";
    private String nombreUsuario;
    private Collection<? extends GrantedAuthority> authorities;

    /**
     * Constructor para JwtDto.
     *
     * @param token         El token JWT.
     * @param nombreUsuario El nombre de usuario.
     * @param authorities   Las autoridades del usuario.
     */
    public JwtDto(String token, String nombreUsuario, Collection<? extends GrantedAuthority> authorities) {
        this.token = token;
        this.nombreUsuario = nombreUsuario;
        this.authorities = authorities;
    }

    /**
     * Obtiene el token JWT.
     *
     * @return El token JWT.
     */
    public String getToken() {
        return token;
    }

    /**
     * Establece el token JWT.
     *
     * @param token El token JWT.
     */
    public void setToken(String token) {
        this.token = token;
    }

    /**
     * Obtiene el tipo de token (Bearer).
     *
     * @return El tipo de token.
     */
    public String getBearer() {
        return bearer;
    }

    /**
     * Establece el tipo de token (Bearer).
     *
     * @param bearer El tipo de token.
     */
    public void setBearer(String bearer) {
        this.bearer = bearer;
    }

    /**
     * Obtiene el nombre de usuario.
     *
     * @return El nombre de usuario.
     */
    public String getNombreUsuario() {
        return nombreUsuario;
    }

    /**
     * Establece el nombre de usuario.
     *
     * @param nombreUsuario El nombre de usuario.
     */
    public void setNombreUsuario(String nombreUsuario) {
        this.nombreUsuario = nombreUsuario;
    }

    /**
     * Obtiene las autoridades del usuario.
     *
     * @return Las autoridades del usuario.
     */
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    /**
     * Establece las autoridades del usuario.
     *
     * @param authorities Las autoridades del usuario.
     */
    public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
        this.authorities = authorities;
    }
}
```

## DTO LoginUsuario

La clase `LoginUsuario` es un objeto de transferencia de datos (DTO) que se utiliza para capturar y transportar las credenciales de acceso de un usuario, incluyendo su nombre de usuario y contraseña. Este DTO se emplea principalmente en los procesos de autenticación, permitiendo que el cliente envíe de manera estructurada la información de inicio de sesión al backend. La clase proporciona métodos de acceso y modificación para ambos atributos, garantizando una manipulación segura y organizada de los datos sensibles durante el proceso de autenticación en la aplicación.

```java
/**
 * DTO para los datos de inicio de sesión del usuario.
 */
public class LoginUsuario {

    // Nombre de usuario
    private String nombreUsuario;

    // Contraseña del usuario
    private String password;

    /**
     * Obtiene el nombre de usuario.
     *
     * @return El nombre de usuario.
     */
    public String getNombreUsuario() {
        return nombreUsuario;
    }

    /**
     * Establece el nombre de usuario.
     *
     * @param nombreUsuario El nombre de usuario.
     */
    public void setNombreUsuario(String nombreUsuario) {
        this.nombreUsuario = nombreUsuario;
    }

    /**
     * Obtiene la contraseña del usuario.
     *
     * @return La contraseña del usuario.
     */
    public String getPassword() {
        return password;
    }

    /**
     * Establece la contraseña del usuario.
     *
     * @param password La contraseña del usuario.
     */
    public void setPassword(String password) {
        this.password = password;
    }
}
```

## DTO Mensaje

La clase `Mensaje` es un objeto de transferencia de datos (DTO) diseñado para encapsular mensajes de respuesta que se envían desde el backend al cliente. Este DTO proporciona una estructura sencilla para devolver información relevante, como notificaciones de éxito, advertencias o errores, permitiendo una comunicación clara y consistente en la aplicación. La clase incluye un constructor para inicializar el mensaje y métodos de acceso para obtener y modificar su contenido, lo que facilita su uso en diferentes contextos de respuesta dentro del sistema.

```java
/**
 * DTO para mensajes de respuesta.
 */
public class Mensaje implements RespuestaDto {

    // El mensaje de respuesta
    private String mensaje;

    /**
     * Constructor para Mensaje.
     *
     * @param mensaje El mensaje de respuesta.
     */
    public Mensaje(String mensaje) {
        this.mensaje = mensaje;
    }

    /**
     * Obtiene el mensaje de respuesta.
     *
     * @return El mensaje de respuesta.
     */
    public String getMensaje() {
        return mensaje;
    }

    /**
     * Establece el mensaje de respuesta.
     *
     * @param mensaje El mensaje de respuesta.
     */
    public void setMensaje(String mensaje) {
        this.mensaje = mensaje;
    }
}
```

## SecurityUtils



```java
/**
 * Utilidades de seguridad para obtener información de las solicitudes HTTP.
 */
public class SecurityUtils {

    private static final Logger logger = LoggerFactory.getLogger(SecurityUtils.class);

    /**
     * Obtiene la IP del cliente desde la solicitud HTTP.
     *
     * @param request El objeto HttpServletRequest.
     * @return La IP del cliente.
     */
    public static String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Real-IP");
        if (xfHeader == null) {
            // logger.error("Cabecera X-Real-IP con valor null.");
            return request.getRemoteAddr();
        }
        // logger.info("Cabecera X-Real-IP con valor: " + xfHeader);
        return xfHeader.split(",")[0];
    }

    /**
     * Obtiene la URL completa de la solicitud HTTP.
     *
     * @param request El objeto HttpServletRequest.
     * @return La URL completa de la solicitud.
     */
    public static String getFullURL(HttpServletRequest request) {
        StringBuilder requestURL = new StringBuilder(request.getRequestURL().toString());
        String queryString = request.getQueryString();

        if (queryString == null) {
            return requestURL.toString();
        } else {
            return requestURL.append('?').append(queryString).toString();
        }
    }

    /**
     * Obtiene el token JWT de la cabecera de autorización de la solicitud HTTP.
     *
     * @param request El objeto HttpServletRequest.
     * @return El token JWT si está presente, de lo contrario null.
     */
    public static String getToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if(header != null && header.startsWith("Bearer")) {
            return header.replace("Bearer ", "");
        }
        return null;
    }
}
```

## Probando el servicio

  
En esta sección se describen los pasos para probar la configuración de seguridad de la aplicación utilizando **Postman**. A continuación, se explicarán las diferentes pruebas que se pueden realizar, incluyendo la autenticación con JWT y el acceso a rutas protegidas.

**1. Iniciar sesión y obtener un token JWT**

  

Para obtener un token JWT válido que permita acceder a las rutas protegidas, se debe realizar una solicitud **POST** al endpoint de autenticación.



**Pasos:**

1.  Abrir Postman y seleccionar el método POST.
2.  Introducir la URL de autenticación:
```html
http://localhost:8080/auth/login
```
3.  Ir a la pestaña Body y seleccionar raw con formato JSON.
4.  Introducir las credenciales en el cuerpo de la petición, por ejemplo:
```json
{
    "nombreUsuario": "user497",
    "password": "password"
}
```
5. Hacer clic en el botón Send.
6. Verificar que la respuesta contiene el token JWT, que se verá como:
```json
{
    "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyNDk3IiwiZXhwIjoxNjk3MTY0Mzg3fQ.MEQCIQCy4B...",
    "nombreUsuario": "user497",
    "authorities": [
        {
            "authority": "ROLE_USER"
        }
    ],
    "bearer": "Bearer"
}
```
7.  Copiar el valor del token para utilizarlo en las siguientes solicitudes.

**2. Acceder a una ruta pública**

Las rutas públicas no requieren autenticación, por lo que se pueden acceder sin necesidad de enviar un token en la cabecera de autorización.

**Pasos:**

1.  Seleccionar el método GET.

2.  Introducir la URL de una ruta pública:
```html
http://localhost:8080/public/list
```
3.  Hacer clic en Send y verificar que la respuesta devuelva datos de usuarios sin restricciones:
```json
[
    {
        "id": 1,
        "userName": "user497",
        "password": "$2a$10$ZHRNUE1onM08B...",
        "role": "USER"
    },
    {
        "id": 2,
        "userName": "user615",
        "password": "$2a$10$ZHRNUE1onM08B...",
        "role": "USER"
    }
]
```

**3. Acceder a una ruta protegida con el token JWT**

Las rutas protegidas requieren que se envíe el token JWT obtenido en el paso 1 en la cabecera de autorización.

**Pasos:**

1.  Seleccionar el método GET.
2.  Introducir la URL de la ruta protegida, por ejemplo:
  ```html
  http://localhost:8080/user/list
  ```
3. Ir a la pestaña Authorization y seleccionar el tipo Bearer Token. En la casilla Token, introducir el token obtenido previamente.
4.  Hacer clic en Send.  

Si el token es válido, se recibirá una respuesta con los datos protegidos. En caso contrario, se recibirá un error 401 Unauthorized.

**4. Intentar acceder a una ruta protegida sin token**

Si intentamos acceder a una ruta protegida sin enviar el token, se recibirá un error de autenticación.

**Pasos:**

1.  Seleccionar el método GET.
2.  Introducir la URL de la ruta protegida, por ejemplo:
```html
http://localhost:8080/user/list
```
3.  No incluir ningún valor en la cabecera de autorización.
4.  Hacer clic en Send.

**Respuesta esperada:**

    Error 401. 


## Seguridad basada en roles y permisos

La implementación de control de acceso basado en roles en Spring Security permite restringir el acceso a ciertos endpoints según los permisos de los usuarios. Esto se logra utilizando la anotación `@PreAuthorize`, que facilita la definición de restricciones a nivel de método, asegurando un control preciso sobre qué usuarios pueden acceder a qué funcionalidades.

Para utilizar esta funcionalidad, es necesario habilitar la anotación `@EnableMethodSecurity` en la clase de configuración de seguridad, `SecurityConfig`. Esto permite que Spring Security procese las anotaciones de autorización en los métodos de los controladores.

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    // Configuración de seguridad aquí...
}
```

Con esta configuración habilitada, se pueden utilizar anotaciones como `@PreAuthorize` para definir el acceso a los métodos en función del rol del usuario autenticado. Por ejemplo, en la clase `AdminController`, se restringe el acceso al método `adminAccess()` solo a usuarios con el rol `ADMIN`:

```java
@RestController
@RequestMapping("/admin")
public class AdminController {

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/dashboard")
    public ResponseEntity<String> adminAccess() {
        return ResponseEntity.ok("Acceso permitido solo para administradores.");
    }
}
```

En este caso, antes de que el método `adminAccess` se ejecute, Spring Security verifica si el usuario autenticado posee el rol `ADMIN`. Si el usuario tiene el rol requerido, se le concede acceso; de lo contrario, se devuelve un error `403 (Forbidden)`, indicando que el acceso está restringido.

Para facilitar las pruebas, se ha añadido un nuevo endpoint en la clase `PublicController` que permite crear usuarios con el rol de administrador de forma aleatoria:

```java
    /**
     * Endpoint para crear un nuevo usuario aleatorio y devolver la lista actualizada de usuarios.
     *
     * @return ResponseEntity con la lista actualizada de usuarios y el estado HTTP OK.
     */
    @GetMapping("/newrandomadmin")
    public ResponseEntity<List<User>> newRandomadmin() {
        // Crear un nuevo usuario con un nombre de usuario aleatorio y una contraseña codificada
        User user = new User();
        user.setUserName("user" + (int)(Math.random() * 1000));
        user.setPassword(passwordEncoder.encode("password"));
        user.setRole("ADMIN");

        // Guardar el nuevo usuario en la base de datos
        userService.saveUser(user);

        // Obtener la lista actualizada de todos los usuarios
        List<User> usuarios = userService.getAllUsers();
        // Devolver la lista actualizada de usuarios con el estado HTTP OK
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(usuarios);
    }
```

Para probar la configuración de seguridad, se pueden seguir los siguientes pasos:

1.	Crear un usuario administrador:
Realizar una solicitud GET al endpoint http://localhost:8080/public/newrandomadmin. Esto generará un usuario con rol ADMIN y lo almacenará en la base de datos.
2.	Autenticarse como administrador:
Enviar una solicitud POST a http://localhost:8080/auth/login con las credenciales del usuario recién creado para obtener un token JWT válido.
3.	Acceder al endpoint protegido:
Usar el token recibido para realizar una solicitud GET al endpoint protegido http://localhost:8080/admin/dashboard, incluyéndolo en la cabecera de autorización con formato Bearer <token>.

Si el usuario cuenta con el rol adecuado, se recibirá una respuesta con el mensaje "Acceso permitido solo para administradores.". En caso contrario, se devolverá un error HTTP 403 indicando que el acceso no está autorizado.

## Auditoría y registro de eventos de seguridad

Para mejorar la seguridad de la aplicación, es importante llevar un registro de eventos clave relacionados con la autenticación, como inicios de sesión exitosos o intentos fallidos de acceso. Spring Security permite registrar estos eventos mediante la escucha de eventos de seguridad.

Se puede implementar una clase de auditoría utilizando la anotación @EventListener para capturar eventos de autenticación y registrarlos en los logs del sistema:

```java
@Component
public class SecurityEventListener {

    private static final Logger logger = LoggerFactory.getLogger(SecurityEventListener.class);

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        logger.info("Inicio de sesión exitoso para el usuario: {}", event.getAuthentication().getName());
    }

    @EventListener
    public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) {
        logger.warn("Intento de inicio de sesión fallido con usuario: {}", event.getAuthentication().getName());
    }
}
```

- Registro de inicios de sesión exitosos:
Cuando un usuario se autentica correctamente, el evento AuthenticationSuccessEvent se dispara y el sistema registra un mensaje con el nombre de usuario.
- Registro de intentos de acceso fallidos:
Si un usuario introduce credenciales incorrectas, el evento AuthenticationFailureBadCredentialsEvent es capturado y se registra un intento fallido con el nombre de usuario.

Para comprobar esta nueva funcionalidad, podemos realizar diferentes llamadas al servicio de login `localhost:8080/auth/login` tanto con un login correcto como con uno incorrecto y comprobar el mensaje que aparece en el log.

## Contenido avanzado

En este apartado se exploran configuraciones avanzadas de seguridad en Spring Security, proporcionando un enfoque detallado sobre dos formas principales de configuración: la automática, que permite una implementación rápida con valores predeterminados adecuados para aplicaciones simples, y la configuración personalizada, que brinda un control granular sobre la autenticación y autorización. Además, se profundiza en aspectos esenciales como la gestión de CORS (Cross-Origin Resource Sharing) para permitir solicitudes entre dominios de manera segura, la implementación de cabeceras HTTP de seguridad para proteger la aplicación contra ataques comunes como Clickjacking o inyección de contenido, y las mejores prácticas para garantizar un entorno seguro y robusto en aplicaciones empresariales.

### Configuración de seguridad en Spring

Spring Boot proporciona dos formas principales de configurar la seguridad en una aplicación: mediante la configuración automática y mediante una configuración personalizada utilizando la anotación `@EnableWebSecurity` (la vista previamente).

#### Configuración Automática de Spring Security

Spring Boot aplica una configuración de seguridad predeterminada cuando se incluye la dependencia de Spring Security en el proyecto.
Esta configuración predeterminada incluye protección contra ataques CSRF, autenticación HTTP básica, formularios de inicio de sesión predeterminados y autorización de solicitudes.

**Ventajas:**

- Simplicidad: No requiere configuración adicional, lo que facilita la configuración inicial de la seguridad.
- Rápido de implementar: Ideal para aplicaciones simples o prototipos donde la configuración de seguridad avanzada no es necesaria.

**Inconvenientes:**

- Limitada personalización: No permite personalizar las reglas de seguridad según las necesidades específicas de la aplicación.
- Configuración predeterminada: La configuración predeterminada puede no ser adecuada para todas las aplicaciones, especialmente aquellas con requisitos de seguridad específicos.

#### Configuración Personalizada con @EnableWebSecurity

La anotación `@EnableWebSecurity` permite activar la configuración personalizada de seguridad web en una aplicación Spring. Facilita la definición de una clase de configuración donde se pueden establecer reglas detalladas de seguridad utilizando un bean `SecurityFilterChain`, lo que brinda un control completo sobre aspectos como la autenticación, autorización, manejo de excepciones y otras configuraciones avanzadas de seguridad.

**Ventajas:**

- Flexibilidad: Permite personalizar completamente la configuración de seguridad según las necesidades específicas de la aplicación.
Control detallado: Ofrece control detallado sobre las reglas de seguridad, incluyendo la configuración de roles, permisos, y políticas de autenticación.

**Inconvenientes:**

- Complejidad: Requiere una configuración más detallada y puede ser más complejo de implementar.
- Mayor esfuerzo inicial: Necesita más tiempo y esfuerzo para configurar en comparación con la configuración automática.

Ejemplo de Configuración Personalizada:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private JwtEntryPoint jwtEntryPoint;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/auth/**").permitAll()
                .anyRequest().authenticated()
            )
            .exceptionHandling(exception -> exception
                .authenticationEntryPoint(jwtEntryPoint)
            )
            .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            );
        return http.build();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }
}
```



### Seguridad con CORS

El Cross-Origin Resource Sharing (CORS) es un mecanismo de seguridad que permite a las aplicaciones web en un dominio realizar solicitudes a recursos alojados en otro dominio. De forma predeterminada, los navegadores restringen las solicitudes de origen cruzado por motivos de seguridad, pero en aplicaciones modernas, como aquellas con frontend y backend separados, es fundamental habilitar CORS correctamente.

Spring Security permite configurar CORS de manera detallada para controlar qué orígenes pueden acceder a los recursos de la aplicación, qué métodos HTTP están permitidos y si se deben enviar credenciales en las solicitudes.

**Configuración de CORS en Spring Security**

Para permitir solicitudes desde un frontend alojado en un dominio diferente, es necesario configurar CORS en la clase de configuración de seguridad. Esto se puede hacer agregando una política de CORS en la definición de SecurityFilterChain de la clase SecurityConfig:

```java
/**
 * Clase de configuración de seguridad. Se definen las reglas de seguridad.
 * SecurityConfig
 */
@Configuration
public class SecurityConfig {

    // Inyección de dependencias para manejar errores de autenticación
    @Autowired
    private JwtEntryPoint jwtEntryPoint;

    // Definición del filtro de autenticación JWT como un bean
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }

    /**
     * Configuración de la cadena de filtros de seguridad.
     *
     * @param http Objeto HttpSecurity para configurar la seguridad HTTP.
     * @return SecurityFilterChain configurado.
     * @throws Exception en caso de error en la configuración de seguridad.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Desactivar CSRF para simplificar la configuración
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            // Configuración de las reglas de autorización
            .authorizeHttpRequests(auth -> auth
                // Permitir acceso a rutas públicas
                .requestMatchers("/public/**").permitAll()
                // Permitir acceso a rutas de autenticación
                .requestMatchers("/auth/**").permitAll()
                // Requerir autenticación para cualquier otra ruta
                .anyRequest().authenticated()
            )
            // Manejar errores de autenticación con JwtEntryPoint
            .exceptionHandling(exception -> exception
                .authenticationEntryPoint(jwtEntryPoint)
            )
            // Añadir el filtro de autenticación JWT antes del filtro de autenticación de usuario y contraseña
            .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
            // Configuración de la página de inicio de sesión personalizada (opcional)
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            );
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://127.0.0.1:5500", "http://localhost:5500")); // Asegúrate de agregar la URL de tu archivo HTML
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        configuration.setAllowCredentials(true);
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
    
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * Definición del bean AuthenticationManager para manejar la autenticación.
     *
     * @param authenticationConfiguration Objeto AuthenticationConfiguration para configurar el AuthenticationManager.
     * @return AuthenticationManager configurado.
     * @throws Exception en caso de error en la configuración del AuthenticationManager.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * Definición del bean PasswordEncoder para codificar las contraseñas.
     *
     * @return PasswordEncoder configurado.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

- Habilitación de CORS: Se añade la configuración de CORS en la cadena de seguridad HTTP mediante cors(cors -> cors.configurationSource(corsConfigurationSource())), indicando que se utilizará una configuración personalizada.
- Origen permitido: La propiedad setAllowedOrigins(List.of("http://localhost:5500")) permite solicitudes únicamente desde el frontend alojado en el puerto 5500 (servidor de pruebas local).
- Métodos permitidos: Con setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE")), se restringen los métodos HTTP a aquellos necesarios para la comunicación con el backend.
- Cabeceras permitidas: La configuración setAllowedHeaders(List.of("Authorization", "Content-Type")) permite solo ciertas cabeceras en las solicitudes, asegurando control sobre la información enviada.
- Credenciales: setAllowCredentials(true) permite el envío de cookies y encabezados de autorización en las solicitudes, lo cual es necesario cuando se requiere autenticación basada en tokens o cookies de sesión.

Para verificar que la configuración de CORS funciona correctamente, se puede realizar una solicitud desde un frontend local mediante un archivo HTML sencillo:

```html
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Prueba de CORS</title>
</head>
<body>
    <h1>Probar CORS</h1>
    <button onclick="testCors()">Probar CORS</button>

    <script>
        function testCors() {
            fetch('http://localhost:8080/public/cors-test', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Error de CORS o solicitud: ${response.status}`);
                }
                return response.text();
            })
            .then(data => alert('Respuesta del servidor: ' + data))
            .catch(error => alert('Error: ' + error));
        }
    </script>
</body>
</html>
```

Ejecución de la prueba con Live Server:
1.	Abre el archivo cors-test.html en Visual Studio Code (VSCode).
2.	Instala la extensión Live Server (si no la tienes instalada).
3.	Haz clic derecho sobre el archivo y selecciona “Open with Live Server”, lo que abrirá el archivo en http://127.0.0.1:5500/cors-test.html.
4.	Pulsa el botón “Probar CORS”, que enviará una solicitud GET al backend.
5.	Si CORS está configurado correctamente, verás una alerta con el mensaje "CORS funciona correctamente.".
6. Puedes probar a cambiar el puerto configurado para el CORS de la clase SecurityConfig de 5500 por el 5600, por ejemplo, y comprobar que CORS ya no permite el acceso.

### Seguridad con cabeceras HTTP

Spring Security incorpora por defecto varias medidas de protección mediante cabeceras HTTP, proporcionando una capa adicional de seguridad contra ataques web comunes, como Clickjacking, Cross-Site Scripting (XSS) y inyección de contenido no seguro. Estas cabeceras ayudan a mitigar amenazas sin necesidad de configuraciones adicionales en la mayoría de los casos, permitiendo que las aplicaciones sean más seguras desde el inicio.

Protecciones incluidas por defecto

Cuando se utiliza Spring Security, se aplican automáticamente las siguientes cabeceras de seguridad:
- Protección contra Clickjacking (X-Frame-Options): Esta cabecera evita que la aplicación sea cargada en un iframe de otro dominio, protegiendo contra ataques de Clickjacking. Spring Security establece por defecto X-Frame-Options: DENY, bloqueando cualquier intento de incrustación.
- Protección contra XSS (X-XSS-Protection): Aunque los navegadores modernos dependen más de la Política de Seguridad de Contenidos (CSP), Spring Security configura la cabecera X-XSS-Protection: 0 para deshabilitarla, ya que en algunos navegadores antiguos podría generar falsos positivos.
- Control de tipo de contenido (X-Content-Type-Options): La cabecera X-Content-Type-Options: nosniff impide que los navegadores interpreten tipos de contenido incorrectos, mitigando ataques de inyección de contenido malicioso.
- Política de seguridad de contenido (CSP): Spring Security no configura una política de CSP por defecto, pero permite definirla manualmente si se requiere una protección más estricta contra la ejecución de scripts no autorizados.

**Configuración personalizada de cabeceras de seguridad**

Aunque muchas de estas protecciones ya están habilitadas de forma predeterminada, es posible personalizar algunas cabeceras para reforzar la seguridad según las necesidades específicas de la aplicación. A continuación, se muestra un ejemplo de cómo se pueden agregar configuraciones adicionales si fuera necesario:

```java
/**
 * Clase de configuración de seguridad. Se definen las reglas de seguridad.
 * SecurityConfig
 */
@Configuration
public class SecurityConfig {

    // Inyección de dependencias para manejar errores de autenticación
    @Autowired
    private JwtEntryPoint jwtEntryPoint;

    // Definición del filtro de autenticación JWT como un bean
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }

    /**
     * Configuración de la cadena de filtros de seguridad.
     *
     * @param http Objeto HttpSecurity para configurar la seguridad HTTP.
     * @return SecurityFilterChain configurado.
     * @throws Exception en caso de error en la configuración de seguridad.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Desactivar CSRF para simplificar la configuración
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            // Configuración de las reglas de autorización
            .authorizeHttpRequests(auth -> auth
                // Permitir acceso a rutas públicas
                .requestMatchers("/public/**").permitAll()
                // Permitir acceso a rutas de autenticación
                .requestMatchers("/auth/**").permitAll()
                // Requerir autenticación para cualquier otra ruta
                .anyRequest().authenticated()
            )
            // Manejar errores de autenticación con JwtEntryPoint
            .exceptionHandling(exception -> exception
                .authenticationEntryPoint(jwtEntryPoint)
            )
            // Añadir el filtro de autenticación JWT antes del filtro de autenticación de usuario y contraseña
            .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
            // Configuración de la página de inicio de sesión personalizada (opcional)
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            )
            .headers(headers -> headers
            .contentSecurityPolicy(csp -> csp.policyDirectives("script-src 'self'"))  // Restringir scripts solo al mismo dominio
            );
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://127.0.0.1:5500", "http://localhost:5500")); // Asegúrate de agregar la URL de tu archivo HTML
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        configuration.setAllowCredentials(true);
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
    
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * Definición del bean AuthenticationManager para manejar la autenticación.
     *
     * @param authenticationConfiguration Objeto AuthenticationConfiguration para configurar el AuthenticationManager.
     * @return AuthenticationManager configurado.
     * @throws Exception en caso de error en la configuración del AuthenticationManager.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * Definición del bean PasswordEncoder para codificar las contraseñas.
     *
     * @return PasswordEncoder configurado.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

En este ejemplo, se ha agregado una configuración personalizada de Content Security Policy (CSP) que restringe la ejecución de scripts únicamente al dominio de la aplicación, reduciendo el riesgo de ataques de inyección de código malicioso.

**Verificación de las cabeceras de seguridad**

Para comprobar las cabeceras de seguridad aplicadas por Spring Security, se puede utilizar una herramienta como curl o las herramientas de desarrollo del navegador:

```bash
curl -I http://localhost:8080/public/cors-test
```
El resultado esperado debe incluir cabeceras como:
```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Content-Security-Policy: script-src 'self'
```

Estas configuraciones permiten asegurar que la aplicación web cumple con buenas prácticas de seguridad, mitigando ataques comunes relacionados con la manipulación de contenido y la ejecución de código no autorizado.

Spring Security proporciona un conjunto de protecciones por defecto que cubren la mayoría de los escenarios de seguridad, reduciendo la necesidad de configuraciones adicionales. Sin embargo, en aplicaciones con requisitos más estrictos, es recomendable revisar las políticas de seguridad y ajustarlas según las necesidades específicas del proyecto.

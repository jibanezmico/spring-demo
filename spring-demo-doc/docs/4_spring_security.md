# Configuración de Seguridad en Spring Security

En esta sección se describe la configuración de seguridad de la aplicación mediante **Spring Security**,
incluyendo la gestión de autenticación y autorización basada en tokens JWT.

Para ello debemos añadir en nuestro pom.xml las siguientes dependencias:

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

## Configuración de Spring Security

La clase `SecurityConfig` define las reglas de seguridad de la aplicación, gestionando la autenticación
y autorización de las rutas.

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
````

### Explicación:

- **Filtro de autenticación JWT:** Se encarga de interceptar y validar tokens en cada solicitud.
- **Gestión de credenciales:** Extrae el token JWT de la cabecera de autorización y valida su autenticidad.
- **Autenticación en el contexto de seguridad:** Establece la autenticación si el token es válido.

##JwtAuthenticationFilter

La clase `JwtAuthenticationFilter` es un filtro de Spring Security que intercepta las solicitudes HTTP para validar tokens JWT. Su función es extraer el token de la cabecera de autorización, validarlo mediante JwtProvider y, si es correcto, establecer la autenticación del usuario en el contexto de seguridad de Spring. Se ejecuta antes del filtro de autenticación estándar, garantizando que solo las solicitudes autenticadas accedan a los recursos protegidos.

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

### Explicación:
- **Extracción del token JWT:** Se obtiene el token de la cabecera de autorización.
- **Validación del token:** Se verifica la autenticidad del token recibido.
- **Establecimiento de la autenticación:** Si el token es válido, se autentica al usuario en el contexto de seguridad de Spring.

## Punto de Entrada de Autenticación

La clase `JwtEntryPoint` maneja los errores de autenticación y envía respuestas adecuadas cuando el usuario no está autorizado.

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

### Explicación:

- **Gestión de errores:** Se encarga de devolver un error 401 cuando no se proporciona una autenticación válida.
- **Mensajes personalizados:** Devuelve mensajes específicos dependiendo del tipo de error.

## Proveedor de Tokens JWT

La clase `JwtProvider` se encarga de la generación y validación de tokens JWT para autenticar usuarios.

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

### Explicación:

- **Generación de tokens:** Crea tokens JWT válidos con información del usuario autenticado.
- **Validación de tokens:** Verifica la autenticidad de un token recibido.
- **Extracción de usuario:** Obtiene el nombre de usuario a partir del token JWT.

## Controlador de Usuarios

La clase `UserController` proporciona los endpoints necesarios para la gestión de usuarios.

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

### Explicación:

- **Operaciones CRUD:** Permite la obtención de usuarios a través de su ID.
- **Uso de `UserService`:** Delegación de la lógica de negocio al servicio correspondiente.

## Servicio de Usuarios

La clase `UserService` implementa la lógica de negocio relacionada con los usuarios.

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

### Explicación:

- **Gestión de usuarios:** Permite obtener y manipular los datos de usuarios.
- **Interacción con la base de datos:** Se apoya en `UserRepository` para realizar operaciones de persistencia.

## Repositorio de Usuarios

La interfaz `UserRepository` define las operaciones de acceso a la base de datos utilizando Spring Data JPA.

```java
package com.demospring.security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.demospring.security.entity.User;

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

### Explicación:

- **Persistencia:** Proporciona métodos automáticos para la manipulación de la entidad usuario.
- **Uso de JPA:** Define operaciones de base de datos de forma declarativa.

## Contenido avanzado

En este apartado se amplían algunos conceptos avanzados de seguridad en **Spring Security** y **JWT**, abordando aspectos adicionales como:

### Seguridad basada en roles y permisos

Spring Security permite definir y controlar accesos a nivel de métodos mediante anotaciones como:

```java
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin")
public String adminAccess() {
    return "Acceso permitido solo para administradores.";
}
```

Con la anotación `@EnableGlobalMethodSecurity(prePostEnabled = true)` en la clase de configuración de seguridad, se pueden proteger métodos específicos según los roles de los usuarios.

### Seguridad con OAuth2 y OpenID Connect

Además de JWT, **OAuth2** y **OpenID Connect** son estándares ampliamente utilizados para la autenticación federada y delegada. Spring Security proporciona integración con estos estándares mediante la dependencia:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
```

Para configurar un cliente OAuth2 en `application.properties`:

```properties
spring.security.oauth2.client.registration.google.client-id=TU_CLIENT_ID
spring.security.oauth2.client.registration.google.client-secret=TU_CLIENT_SECRET
spring.security.oauth2.client.registration.google.redirect-uri=http://localhost:8080/login/oauth2/code/google
spring.security.oauth2.client.registration.google.scope=openid,profile,email
```

### Seguridad con CORS

CORS (Cross-Origin Resource Sharing) permite el acceso de aplicaciones web desde dominios distintos. Para habilitar CORS en Spring Security:

```java
@Configuration
public class CorsConfig {

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("http://localhost:3000")
                        .allowedMethods("GET", "POST", "PUT", "DELETE")
                        .allowCredentials(true);
            }
        };
    }
}
```

### Seguridad con cabeceras HTTP

Spring Security permite configurar la seguridad mediante cabeceras HTTP, como por ejemplo:

```java
http
    .headers(headers -> headers
        .frameOptions().disable()  // Permitir iframes desde el mismo origen
        .contentSecurityPolicy("script-src 'self'")  // Política de seguridad de contenido
        .xssProtection().block(true)  // Protección contra ataques XSS
    );
```

### Auditoría y registro de eventos de seguridad

Para registrar eventos de seguridad como inicios de sesión exitosos o fallidos, se puede implementar un auditor personalizado:

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

### Actividad práctica

- Configurar una aplicación de prueba que incluya:
  - Protección de rutas mediante roles y permisos con anotaciones.
  - Integración con OAuth2 utilizando Google como proveedor de autenticación.
  - Configuración de CORS para permitir solicitudes desde un frontend React.
  - Implementación de auditoría para registrar eventos de autenticación.

Este apartado proporciona conocimientos avanzados sobre la seguridad en aplicaciones Spring Boot, ayudando a fortalecer la protección de los recursos y garantizar la seguridad de los datos.

## Capítulo 4: Seguridad con Spring Security y JWT

### Introducción a Spring Security

Spring Security es un framework que proporciona autenticación y autorización en aplicaciones Java. Permite proteger aplicaciones contra amenazas comunes como ataques de fuerza bruta, CSRF y XSS, y gestionar roles y permisos de usuarios.

### Configuración de Seguridad

La configuración de seguridad se realiza en una clase anotada con `@Configuration`. Esta clase extiende `WebSecurityConfigurerAdapter` y sobreescribe métodos para definir cómo se gestionará la seguridad en la aplicación.

### Dependencias
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

### Actividad Práctica

- **Configurar Spring Security**:
```java
@Configuration
public class SecurityConfig {
    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Autowired
    private JwtEntryPoint jwtEntryPoint;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }

    /**
    * Configura el AuthenticationManagerBuilder con el UserDetailsService y el PasswordEncoder.
    * @param auth el AuthenticationManagerBuilder
    * @throws Exception en caso de error
    */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        logger.info("Configurando AuthenticationManagerBuilder");
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    /**
    * Configura la seguridad HTTP, deshabilitando CSRF, permitiendo el acceso público a las rutas de autenticación,
    * y requiriendo autenticación para otras rutas. También configura el manejo de excepciones y la política de creación de sesiones.
    * @param http el HttpSecurity
    * @throws Exception en caso de error
    */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        logger.info("Configurando HttpSecurity");
        http.csrf().disable()
            .authorizeRequests()
            .antMatchers("/auth/**").permitAll()
            .anyRequest().authenticated()
            .and()
            .exceptionHandling().authenticationEntryPoint(jwtEntryPoint)
            .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    /**
    * Define el PasswordEncoder que se utilizará para codificar las contraseñas.
    * @return el PasswordEncoder
    */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
    * Define el AuthenticationManager que se utilizará para la autenticación.
    * @return el AuthenticationManager
    * @throws Exception en caso de error
    */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
```

Esta clase `SecurityConfig` extiende `WebSecurityConfigurerAdapter` y se encarga de la configuración de seguridad de la aplicación. Aquí se configuran varios aspectos importantes y se utiliza un Logger para registrar eventos importantes:

- `configure(AuthenticationManagerBuilder auth)`: Configura el `AuthenticationManagerBuilder` con el `UserDetailsService` y el `PasswordEncoder`. Esto asegura que el `AuthenticationManagerBuilder` pueda autenticar usuarios utilizando el `UserDetailsService` y el `PasswordEncoder` configurados.
- `configure(HttpSecurity http)`: Configura la seguridad HTTP, deshabilitando CSRF, permitiendo el acceso público a las rutas de autenticación, y requiriendo autenticación para otras rutas. También configura el manejo de excepciones y la política de creación de sesiones. Esto garantiza que las rutas de autenticación sean accesibles públicamente, mientras que otras rutas requieren autenticación.
- `passwordEncoder()`: Define el `PasswordEncoder` que se utilizará para codificar las contraseñas. Esto asegura que las contraseñas se codifiquen de manera segura antes de almacenarse.
- `authenticationManagerBean()`: Define el `AuthenticationManager` que se utilizará para la autenticación. Esto garantiza que el `AuthenticationManager` esté disponible como un bean en el contexto de la aplicación.

### Criptografía y Cifrado de Contraseñas

### Introducción a la Criptografía

La criptografía es la práctica y el estudio de técnicas para asegurar la comunicación y proteger la información. En el contexto de aplicaciones web, se utiliza para proteger datos sensibles como contraseñas y tokens de autenticación.

### Implementación de Cifrado de Contraseñas y Datos

La implementación de cifrado de contraseñas y datos se realiza utilizando Spring Security y BCrypt. BCrypt es un algoritmo de hashing que incluye un factor de trabajo, lo que lo hace más seguro contra ataques de fuerza bruta.

### Actividad Práctica

- **Implementar cifrado de contraseñas**:
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

### Gestión de JWT

Para gestionar los JWT, necesitamos tres clases en el paquete `security.jwt`:

- **JwtTokenProvider**: Provee métodos para generar y validar tokens JWT.
- **JwtTokenFilter**: Filtro que intercepta las solicitudes HTTP para validar el token JWT.
- **JwtAuthenticationEntryPoint**: Maneja los errores de autenticación.

#### Ejemplo de `JwtTokenProvider`

```java
package com.example.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 * Proveedor de JWT que genera y valida tokens JWT.
 */
@Component
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long validityInMilliseconds;

    /**
     * Genera un token JWT basado en la autenticación del usuario.
     *
     * @param authentication la autenticación del usuario
     * @return el token JWT
     */
    public String createToken(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        Claims claims = Jwts.claims().setSubject(userDetails.getUsername());
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    /**
     * Valida el token JWT.
     *
     * @param token el token JWT
     * @return true si el token es válido, false en caso contrario
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extrae el nombre de usuario del token JWT.
     *
     * @param token el token JWT
     * @return el nombre de usuario
     */
    public String getUsername(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }
}
```

Esta clase `JwtTokenProvider` se encarga de generar y validar tokens JWT. Utiliza la biblioteca `io.jsonwebtoken` para crear y analizar los tokens. Los métodos principales son `createToken`, que genera un token basado en la autenticación del usuario, y `validateToken`, que valida el token.

#### Ejemplo de `JwtTokenFilter`

```java
package com.example.security.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Filtro que intercepta las solicitudes HTTP para validar el token JWT.
 */
@Component
public class JwtTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String token = resolveToken(request);
        if (token != null && jwtTokenProvider.validateToken(token)) {
            String username = jwtTokenProvider.getUsername(token);
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            if (userDetails != null) {
                JwtAuthenticationToken authentication = new JwtAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
```

Esta clase `JwtTokenFilter` extiende `OncePerRequestFilter` y se encarga de interceptar las solicitudes HTTP para validar el token JWT. Si el token es válido, se establece la autenticación en el contexto de seguridad de Spring.

#### Ejemplo de `JwtAuthenticationEntryPoint`

```java
package com.example.security.jwt;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Punto de entrada de autenticación que maneja los errores de autenticación.
 */
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }
}
```

Esta clase `JwtAuthenticationEntryPoint` implementa `AuthenticationEntryPoint` y se encarga de manejar los errores de autenticación. Si una solicitud no autenticada intenta acceder a un recurso protegido, se devuelve un error 401 (Unauthorized).

### Implementación de JWT en Spring Security

La implementación de JWT en Spring Security incluye la creación de un proveedor de JWT, un filtro de autenticación y un punto de entrada de autenticación. Estos componentes se integran en la configuración de seguridad de Spring Security para proporcionar autenticación basada en tokens JWT.

### Actividad Práctica

- **Crear el proveedor de JWT `JwtProvider`**:
```java
@Component
public class JwtProvider {
    private String secret = "secret";

    public String generateToken(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // 10 horas de expiración
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(secret).parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            System.err.println("Token JWT inválido");
        }
        return false;
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
```

### Proteger Endpoints con Roles

Para proteger endpoints con roles, se pueden utilizar las anotaciones `@PreAuthorize` o `@Secured`. A continuación se muestra un ejemplo de cómo proteger un endpoint utilizando `@PreAuthorize`:

- **Habilitar la Seguridad basada en Anotaciones**:
      - Añadir la anotación `@EnableGlobalMethodSecurity` en la clase de configuración de seguridad:
```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // ...existing code...
}
```

- **Proteger un Endpoint con `@PreAuthorize`**:
      - Utilizar la anotación `@PreAuthorize` en el controlador para proteger un endpoint:
```java
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/dashboard")
    public String getAdminDashboard() {
        return "Admin Dashboard";
    }
}
```

En este ejemplo, el endpoint `/api/admin/dashboard` solo será accesible para usuarios con el rol `ADMIN`.

### Explicación del Código

- `@EnableGlobalMethodSecurity(prePostEnabled = true)`: Habilita la seguridad basada en anotaciones en la aplicación.
- `@PreAuthorize("hasRole('ADMIN')")`: Protege el endpoint para que solo sea accesible para usuarios con el rol `ADMIN`.

### Actividad Práctica

- **Proteger un Endpoint con Roles**:
      - Añadir la anotación `@EnableGlobalMethodSecurity(prePostEnabled = true)` en la clase de configuración de seguridad.
      - Utilizar la anotación `@PreAuthorize` en un controlador para proteger un endpoint con un rol específico.
      - Probar el acceso al endpoint con diferentes usuarios para verificar que solo los usuarios con el rol adecuado pueden acceder.

### Validaciones en el Controlador `UserController`

Para agregar validaciones en el controlador `UserController`, se pueden utilizar anotaciones de validación en los métodos del controlador. A continuación se muestra un ejemplo de cómo agregar validaciones en el controlador `UserController`:

```java
package com.example.controller;

import com.example.model.User;
import com.example.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.util.List;

@RestController
@RequestMapping("/users")
@Validated
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping
    public List<User> getAllUsers() {
        return userService.getAllUsers();
    }

    @GetMapping("/{id}")
    public ResponseEntity<User> getUserById(@PathVariable Long id) {
        User user = userService.getUserById(id);
        if (user != null) {
            return ResponseEntity.ok(user);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping
    public ResponseEntity<User> createUser(@Valid @RequestBody User user) {
        User createdUser = userService.createUser(user);
        return ResponseEntity.ok(createdUser);
    }

    @PutMapping("/{id}")
    public ResponseEntity<User> updateUser(@PathVariable Long id, @Valid @RequestBody User user) {
        User updatedUser = userService.updateUser(id, user);
        if (updatedUser != null) {
            return ResponseEntity.ok(updatedUser);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        boolean deleted = userService.deleteUser(id);
        if (deleted) {
            return ResponseEntity.noContent().build();
        } else {
            return ResponseEntity.notFound().build();
        }
    }
}
```

En este ejemplo, se utilizan las anotaciones `@Valid` y `@Validated` para habilitar la validación de los datos de entrada en los métodos del controlador. La anotación `@Valid` se utiliza en los parámetros de los métodos para indicar que los datos de entrada deben ser validados. La anotación `@Validated` se utiliza en la clase del controlador para habilitar la validación a nivel de clase.

Además, se pueden agregar anotaciones de validación en el modelo `User` para definir las reglas de validación. A continuación se muestra un ejemplo de cómo agregar anotaciones de validación en el modelo `User`:

```java
package com.example.model;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

public class User {

    private Long id;

    @NotBlank(message = "El nombre es obligatorio")
    @Size(max = 50, message = "El nombre no puede tener más de 50 caracteres")
    private String name;

    @NotBlank(message = "El correo electrónico es obligatorio")
    @Email(message = "El correo electrónico debe ser válido")
    private String email;

    // Getters y setters
}
```

En este ejemplo, se utilizan las anotaciones `@NotBlank`, `@Size` y `@Email` para definir las reglas de validación en los campos del modelo `User`. Estas anotaciones aseguran que los datos de entrada cumplan con las reglas de validación antes de ser procesados por el controlador.

### Implementación de Sistemas de Autenticación y Autorización Complejos

En aplicaciones más complejas, es común tener la necesidad de gestionar roles y permisos de manera dinámica. Esto implica que los roles y permisos pueden cambiar en tiempo de ejecución y deben ser almacenados y gestionados en una base de datos.

#### Gestión Dinámica de Roles y Permisos

Para gestionar roles y permisos de manera dinámica, se pueden seguir los siguientes pasos:

- **Definir las Entidades de Roles y Permisos**:
    - Crear entidades JPA para representar los roles y permisos en la base de datos.

```java
package com.example.model;

import javax.persistence.*;
import java.util.Set;

@Entity
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name;

    @ManyToMany(mappedBy = "roles")
    private Set<User> users;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "roles_permissions",
        joinColumns = @JoinColumn(name = "role_id"),
        inverseJoinColumns = @JoinColumn(name = "permission_id")
    )
    private Set<Permission> permissions;

    // Getters y setters
}

@Entity
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name;

    @ManyToMany(mappedBy = "permissions")
    private Set<Role> roles;

    // Getters y setters
}
```

- **Actualizar la Entidad de Usuario**:
    - Modificar la entidad `User` para incluir una relación con los roles.

```java
package com.example.model;

import javax.persistence.*;
import java.util.Set;

@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "users_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles;

    // Getters y setters
}
```

- **Configurar el Servicio de Detalles de Usuario**:
    - Implementar `UserDetailsService` para cargar los usuarios y sus roles desde la base de datos.

```java
package com.example.service;

import com.example.model.User;
import com.example.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        Set<GrantedAuthority> authorities = user.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(permission -> new SimpleGrantedAuthority(permission.getName()))
                .collect(Collectors.toSet());

        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
    }
}
```

- **Actualizar la Configuración de Seguridad**:
    - Modificar la configuración de seguridad para utilizar el servicio de detalles de usuario y gestionar roles y permisos.

```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // ...existing code...

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // ...existing code...
    }

    // ...existing code...
}
```

- **Proteger Endpoints con Roles y Permisos**:
    - Utilizar anotaciones como `@PreAuthorize` para proteger los endpoints basados en roles y permisos.

```java
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @PreAuthorize("hasAuthority('ADMIN_DASHBOARD')")
    @GetMapping("/dashboard")
    public String getAdminDashboard() {
        return "Admin Dashboard";
    }
}
```

### Explicación del Código

- **Entidades de Roles y Permisos**: Definen las relaciones entre usuarios, roles y permisos en la base de datos.
- **Servicio de Detalles de Usuario**: Carga los usuarios y sus roles desde la base de datos y convierte los roles en autoridades de Spring Security.
- **Configuración de Seguridad**: Configura Spring Security para utilizar el servicio de detalles de usuario y gestionar roles y permisos.
- **Protección de Endpoints**: Utiliza anotaciones para proteger los endpoints basados en roles y permisos.

### Actividad Práctica

- **Implementar la Gestión Dinámica de Roles y Permisos**:
    - Definir las entidades de roles y permisos.
    - Actualizar la entidad de usuario para incluir una relación con los roles.
    - Implementar el servicio de detalles de usuario para cargar los usuarios y sus roles desde la base de datos.
    - Modificar la configuración de seguridad para utilizar el servicio de detalles de usuario y gestionar roles y permisos.
    - Proteger los endpoints utilizando anotaciones basadas en roles y permisos.

### Implementación de SSL/TLS

SSL/TLS (Secure Sockets Layer / Transport Layer Security) es un protocolo de seguridad que proporciona comunicaciones seguras a través de una red. Para configurar SSL/TLS en una aplicación Spring Boot, se deben seguir los siguientes pasos:

- **Generar un Certificado SSL**:
   - Utilizar `keytool` para generar un certificado SSL autofirmado:
     ```sh
     keytool -genkeypair -alias myalias -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore keystore.p12 -validity 3650
     ```

- **Configurar el Certificado en Spring Boot**:
   - Añadir las siguientes propiedades en el archivo `application.properties`:
     ```properties
     server.port=8443
     server.ssl.key-store=classpath:keystore.p12
     server.ssl.key-store-password=yourpassword
     server.ssl.keyStoreType=PKCS12
     server.ssl.keyAlias=myalias
     ```

- **Redirigir el Tráfico HTTP a HTTPS**:
   - Configurar un redireccionamiento de HTTP a HTTPS en una clase de configuración:
     ```java
     @Configuration
     public class HttpsRedirectConfig {

         @Bean
         public EmbeddedServletContainerCustomizer containerCustomizer() {
             return container -> {
                 if (container instanceof TomcatEmbeddedServletContainerFactory) {
                     TomcatEmbeddedServletContainerFactory tomcat = (TomcatEmbeddedServletContainerFactory) container;
                     tomcat.addAdditionalTomcatConnectors(createHttpConnector());
                 }
             };
         }

         private Connector createHttpConnector() {
             Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
             connector.setScheme("http");
             connector.setPort(8080);
             connector.setSecure(false);
             connector.setRedirectPort(8443);
             return connector;
         }
     }
     ```

### Prácticas de Programación Segura

Además de utilizar Spring Security y JWT, es importante seguir prácticas de programación segura para proteger las aplicaciones contra amenazas comunes. A continuación se presentan algunas prácticas recomendadas:

- **Validación de Entradas**:
   - Validar todas las entradas del usuario para evitar inyecciones y otros ataques.
   - Utilizar anotaciones de validación en los modelos y controladores:
     ```java
     @NotBlank(message = "El nombre es obligatorio")
     @Size(max = 50, message = "El nombre no puede tener más de 50 caracteres")
     private String name;
     ```

- **Protección contra CSRF**:
   - Habilitar la protección CSRF en la configuración de seguridad:
     ```java
     @Override
     protected void configure(HttpSecurity http) throws Exception {
         http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
         // ...existing code...
     }
     ```

- **Protección contra XSS**:
   - Escapar y sanitizar todas las entradas y salidas para evitar ataques XSS.
   - Utilizar bibliotecas como `Jsoup` para sanitizar entradas HTML:
     ```java
     String safeHtml = Jsoup.clean(unsafeHtml, Whitelist.basic());
     ```

- **Gestión Segura de Datos Sensibles**:
   - No almacenar datos sensibles en texto plano.
   - Utilizar algoritmos de hashing y cifrado para proteger datos sensibles como contraseñas y tokens.
   - Configurar el cifrado de datos en tránsito utilizando SSL/TLS.

### Actividad Práctica

- **Configurar SSL/TLS**:
  - Generar un certificado SSL y configurarlo en la aplicación Spring Boot.
  - Configurar el redireccionamiento de HTTP a HTTPS.
  - Verificar que las comunicaciones se realizan de manera segura utilizando HTTPS.

- **Implementar Prácticas de Programación Segura**:
  - Añadir validaciones en los modelos y controladores.
  - Habilitar la protección CSRF en la configuración de seguridad.
  - Escapar y sanitizar entradas y salidas para proteger contra XSS.
  - Configurar el cifrado de datos sensibles y utilizar SSL/TLS para proteger datos en tránsito.

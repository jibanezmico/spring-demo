## Capítulo 4: Seguridad con Spring Security y JWT

### Introducción a Spring Security

Spring Security es un framework que proporciona autenticación y autorización en aplicaciones Java. Permite proteger aplicaciones contra amenazas comunes como ataques de fuerza bruta, CSRF y XSS, y gestionar roles y permisos de usuarios.

### Configuración de Seguridad

La configuración de seguridad se realiza en una clase anotada con `@Configuration`. Esta clase extiende `WebSecurityConfigurerAdapter` y sobreescribe métodos para definir cómo se gestionará la seguridad en la aplicación.

### Actividad Práctica

1. **Configurar Spring Security**:
   ```java
   @Configuration
   @EnableWebSecurity
   public class SecurityConfig extends WebSecurityConfigurerAdapter {
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

1. **Implementar cifrado de contraseñas**:
   ```java
   @Bean
   public PasswordEncoder passwordEncoder() {
       return new BCryptPasswordEncoder();
   }
   ```

### Gestión de JWT

Para gestionar los JWT, necesitamos tres clases en el paquete `security.jwt`:

1. **JwtTokenProvider**: Provee métodos para generar y validar tokens JWT.
2. **JwtTokenFilter**: Filtro que intercepta las solicitudes HTTP para validar el token JWT.
3. **JwtAuthenticationEntryPoint**: Maneja los errores de autenticación.

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

1. **Crear el proveedor de JWT `JwtProvider`**:
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

1. **Habilitar la Seguridad basada en Anotaciones**:
   - Añadir la anotación `@EnableGlobalMethodSecurity` en la clase de configuración de seguridad:
     ```java
     @Configuration
     @EnableWebSecurity
     @EnableGlobalMethodSecurity(prePostEnabled = true)
     public class SecurityConfig extends WebSecurityConfigurerAdapter {
         // ...existing code...
     }
     ```

2. **Proteger un Endpoint con `@PreAuthorize`**:
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

1. **Proteger un Endpoint con Roles**:
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

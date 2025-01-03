## Capítulo 3: Gestión de Datos y Lógica de Negocio con Spring Data

### Introducción

JPA (Java Persistence API) es una especificación para el acceso, persistencia y gestión de datos entre aplicaciones Java y bases de datos relacionales. Hibernate es una implementación de JPA. Spring Data facilita la interacción con bases de datos mediante la definición de repositorios que encapsulan las operaciones CRUD y consultas personalizadas.

### Modelado de Datos con Entidades

Las entidades representan las tablas de la base de datos en el código Java. Cada entidad se mapea a una tabla en la base de datos y sus atributos se mapean a las columnas de la tabla.

### Estrategias de Generación de Claves Primarias

JPA proporciona varias estrategias para la generación de claves primarias:

- **AUTO**: JPA elige automáticamente la estrategia de generación de claves más adecuada para la base de datos.
- **IDENTITY**: Utiliza una columna de identidad en la base de datos para generar las claves primarias.
- **SEQUENCE**: Utiliza una secuencia en la base de datos para generar las claves primarias.
- **TABLE**: Utiliza una tabla especial en la base de datos para generar las claves primarias.

Ejemplo de configuración de estrategias de generación de claves primarias:

```java
@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    // ...existing code...
}
```

### Relaciones entre Entidades

JPA permite definir relaciones entre entidades utilizando anotaciones como `@OneToMany`, `@ManyToOne`, `@OneToOne` y `@ManyToMany`.

Ejemplo de relaciones entre entidades:

```java
@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @OneToMany(mappedBy = "user")
    private List<Order> orders;

    // ...existing code...
}

@Entity
public class Order {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    // ...existing code...
}
```

### Consultas Personalizadas con @Query

Además de las operaciones CRUD estándar, Spring Data JPA permite definir consultas personalizadas utilizando la anotación `@Query`. Aquí hay un ejemplo de cómo definir y utilizar consultas personalizadas en un repositorio:

- **Definir una Consulta Personalizada**:
```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUserName(String userName);

    @Query("SELECT u FROM User u WHERE u.role = :role")
    List<User> findUsersByRole(@Param("role") String role);

    @Query("SELECT u FROM User u WHERE u.userName LIKE %:userName%")
    List<User> findUsersByUserNameContaining(@Param("userName") String userName);
}
```

   En este ejemplo:
   - `@Query("SELECT u FROM User u WHERE u.role = :role")`: Define una consulta personalizada que selecciona usuarios por su rol.
   - `@Query("SELECT u FROM User u WHERE u.userName LIKE %:userName%")`: Define una consulta personalizada que selecciona usuarios cuyo nombre de usuario contiene una cadena específica.
   - `@Param("role")` y `@Param("userName")`: Vinculan los parámetros de la consulta a los parámetros del método.

- **Utilizar la Consulta Personalizada en un Servicio**:
```java
@Service
public class UserService {
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    @Autowired
    private UserRepository userRepository;

    public List<User> getUsersByRole(String role) {
        logger.info("Buscando usuarios con rol: {}", role);
        return userRepository.findUsersByRole(role);
    }

    public List<User> getUsersByUserNameContaining(String userName) {
        logger.info("Buscando usuarios cuyo nombre contiene: {}", userName);
        return userRepository.findUsersByUserNameContaining(userName);
    }
}
```

   En este ejemplo:
   - `getUsersByRole(String role)`: Método del servicio que utiliza la consulta personalizada para obtener usuarios por su rol.
   - `getUsersByUserNameContaining(String userName)`: Método del servicio que utiliza la consulta personalizada para obtener usuarios cuyo nombre de usuario contiene una cadena específica.
   - `Logger`: Utilizado para registrar eventos importantes y errores en la aplicación.

### Consultas Nativas y Criteria API

Spring Data JPA permite definir consultas nativas y utilizar Criteria API para consultas dinámicas.

- **Consultas Nativas**:
```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @Query(value = "SELECT * FROM users WHERE role = ?1", nativeQuery = true)
    List<User> findUsersByRoleNative(String role);
}
```

- **Criteria API**:
```java
@Service
public class UserService {
    @PersistenceContext
    private EntityManager entityManager;

    public List<User> findUsersByCriteria(String role) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<User> query = cb.createQuery(User.class);
        Root<User> user = query.from(User.class);
        query.select(user).where(cb.equal(user.get("role"), role));
        return entityManager.createQuery(query).getResultList();
    }
}
```

### Explicación del Código

- `@Entity`: Indica que la clase es una entidad JPA.
- `@GeneratedValue(strategy = GenerationType.AUTO)`: Configura la estrategia de generación de claves primarias.
- `@OneToMany`, `@ManyToOne`: Define relaciones entre entidades.
- `@Query`: Define consultas personalizadas.
- `CriteriaBuilder`, `CriteriaQuery`: Utilizados para crear consultas dinámicas con Criteria API.

### Beneficios de Usar Spring Data JPA

- **Simplicidad**: Spring Data JPA simplifica la interacción con bases de datos mediante la definición de repositorios y consultas personalizadas.
- **Flexibilidad**: Permite definir consultas personalizadas utilizando JPQL, consultas nativas y Criteria API.

### Actividad Práctica

- **Definir Consultas Personalizadas**:
      - Añadir consultas personalizadas en el repositorio `UserRepository`.
      - Utilizar las consultas personalizadas en el servicio `UserService`.
      - Probar las consultas personalizadas utilizando una herramienta como Postman.

### Lógica de Negocio en Servicios

Los servicios contienen la lógica de negocio de la aplicación y se implementan utilizando la anotación `@Service`. Los servicios interactúan con los repositorios para realizar operaciones en la base de datos.

### Actividad Práctica Integrada

#### Configuración de la Base de Datos Local

Antes de probar el repositorio, es necesario configurar una base de datos local. A continuación, se muestran los pasos para configurar una base de datos MariaDB utilizando Docker:

- **Instalar Docker**:
      - Seguir las instrucciones de instalación en [Docker Downloads](https://www.docker.com/products/docker-desktop).

- **Configurar y ejecutar el contenedor MariaDB**:
      - Clonar el repositorio que contiene el archivo `docker-compose.yml`:
```sh
git clone https://github.com/jibanezmico/DockerUtils.git
cd DockerUtils/MariaDB
```
   - Ejecutar el contenedor:
```sh
docker-compose up -d
```

- **Verificar que el contenedor está en ejecución**:
      - Usar el comando `docker ps` para asegurarse de que el contenedor MariaDB está en ejecución.

- **Configurar el archivo `application.properties`**:
```properties
spring.datasource.url=jdbc:mariadb://localhost:3306/demo_db
spring.datasource.username=mariadbuser
spring.datasource.password=mariadbpass
spring.datasource.driver-class-name=org.mariadb.jdbc.Driver
spring.jpa.hibernate.ddl-auto=update
```

- **Probar la conexión**:
      - Ejecutar la aplicación Spring Boot y verificar que se conecta correctamente a la base de datos.

- **Crear la entidad `User`**:
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
   Esta clase `User` representa una entidad en la base de datos. La anotación `@Entity` indica que esta clase es una entidad JPA. La anotación `@Id` se utiliza para especificar el identificador de la entidad, y `@GeneratedValue` se utiliza para generar automáticamente el valor del identificador.

- **Crear el repositorio `UserRepository`**:
```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUserName(String userName);

    @Query("SELECT u FROM User u WHERE u.role = :role")
    List<User> findUsersByRole(@Param("role") String role);

    @Query("SELECT u FROM User u WHERE u.userName LIKE %:userName%")
    List<User> findUsersByUserNameContaining(@Param("userName") String userName);
}
```
   Esta interfaz `UserRepository` extiende `JpaRepository`, lo que proporciona métodos CRUD estándar para la entidad `User`. Además, se define un método personalizado `findByUserName` para buscar usuarios por nombre de usuario y consultas personalizadas `findUsersByRole` y `findUsersByUserNameContaining` para buscar usuarios por rol y por nombre de usuario, respectivamente.

- **Configurar el archivo `application.properties`**:
```properties
spring.datasource.url=jdbc:mariadb://localhost:3306/demo_db
spring.datasource.username=mariadbuser
spring.datasource.password=mariadbpass
spring.datasource.driver-class-name=org.mariadb.jdbc.Driver
spring.jpa.hibernate.ddl-auto=update
```
   Este archivo `application.properties` contiene la configuración de la base de datos. Se especifica la URL de la base de datos, el nombre de usuario, la contraseña y el controlador JDBC. La propiedad `spring.jpa.hibernate.ddl-auto=update` indica que Hibernate debe actualizar el esquema de la base de datos en función de las entidades definidas.

- **Crear el servicio `UserService`**:
```java
@Service
@Validated
public class UserService implements UserDetailsService {
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.info("Cargando usuario por nombre de usuario: {}", username);
        User user = userRepository.findByUserName(username)
            .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));
        logger.info("Usuario encontrado: {}", username);
        return new org.springframework.security.core.userdetails.User(
            user.getUserName(),
            user.getPassword(),
            Collections.singleton(new SimpleGrantedAuthority("ROLE_" + user.getRole()))
        );
    }

    public List<User> getAllUsers() {
        logger.info("Obteniendo todos los usuarios");
        return userRepository.findAll();
    }

    public User saveUser(@Valid User user) {
        logger.info("Guardando usuario: {}", user.getUserName());
        logger.debug("Datos del usuario: {}", user);
        return userRepository.save(user);
    }

    public Optional<User> getByUserName(String userName) {
        logger.info("Buscando usuario por nombre de usuario: {}", userName);
        return userRepository.findByUserName(userName);
    }

    public List<User> getUsersByRole(String role) {
        logger.info("Buscando usuarios con rol: {}", role);
        return userRepository.findUsersByRole(role);
    }

    public List<User> getUsersByUserNameContaining(String userName) {
        logger.info("Buscando usuarios cuyo nombre contiene: {}", userName);
        return userRepository.findUsersByUserNameContaining(userName);
    }
}
```

   Esta clase `UserService` implementa `UserDetailsService` para proporcionar detalles de usuario a Spring Security. El método `loadUserByUsername` carga un usuario por nombre de usuario y lanza una excepción si el usuario no se encuentra. Además, se proporcionan métodos para obtener todos los usuarios, guardar un usuario, buscar un usuario por nombre de usuario, buscar usuarios por rol y buscar usuarios cuyo nombre de usuario contiene una cadena específica. Se utiliza un Logger para registrar eventos importantes y se aplican validaciones a la entidad `User`.

### Material Avanzado

#### Auditoría en Spring Data JPA

Spring Data JPA proporciona soporte para auditoría de entidades, permitiendo rastrear cambios en los datos. Para habilitar la auditoría, se deben seguir los siguientes pasos:

- **Habilitar la Auditoría**:
      - Añadir la anotación `@EnableJpaAuditing` en una clase de configuración.

```java
@Configuration
@EnableJpaAuditing
public class JpaConfig {
    // ...existing code...
}
```

- **Configurar las Entidades para Auditoría**:
      - Añadir las anotaciones `@CreatedDate`, `@LastModifiedDate`, `@CreatedBy` y `@LastModifiedBy` en las entidades.

```java
@Entity
@EntityListeners(AuditingEntityListener.class)
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @CreatedDate
    private LocalDateTime createdDate;

    @LastModifiedDate
    private LocalDateTime lastModifiedDate;

    @CreatedBy
    private String createdBy;

    @LastModifiedBy
    private String lastModifiedBy;

    // ...existing code...
}
```

#### Uso de Specification para Consultas Dinámicas

Spring Data JPA proporciona la interfaz `Specification` para crear consultas dinámicas.

- **Definir una Especificación**:
```java
public class UserSpecification {
    public static Specification<User> hasRole(String role) {
        return (root, query, cb) -> cb.equal(root.get("role"), role);
    }

    public static Specification<User> userNameContains(String userName) {
        return (root, query, cb) -> cb.like(root.get("userName"), "%" + userName + "%");
    }
}
```

- **Utilizar la Especificación en un Repositorio**:
```java
@Repository
public interface UserRepository extends JpaRepository<User, Long>, JpaSpecificationExecutor<User> {
}
```

- **Utilizar la Especificación en un Servicio**:
```java
@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    public List<User> findUsersByRoleAndUserName(String role, String userName) {
        return userRepository.findAll(Specification.where(UserSpecification.hasRole(role))
                .and(UserSpecification.userNameContains(userName)));
    }
}
```

### Explicación del Código

- `@EnableJpaAuditing`: Habilita la auditoría en Spring Data JPA.
- `@CreatedDate`, `@LastModifiedDate`, `@CreatedBy`, `@LastModifiedBy`: Anotaciones de auditoría.
- `Specification`: Interfaz utilizada para crear consultas dinámicas.

### Beneficios de Usar Auditoría y Specification

- **Auditoría**: Proporciona soporte para auditoría de entidades, permitiendo rastrear cambios en los datos.
- **Consultas Dinámicas**: Permite crear consultas dinámicas utilizando la interfaz `Specification`.

### Actividad Práctica

- **Configurar la Auditoría en una Entidad**:
      - Añadir las anotaciones de auditoría a la entidad `User`.
      - Habilitar la auditoría en una clase de configuración.
      - Probar la auditoría creando y modificando entidades `User`.

- **Crear Consultas Dinámicas con Specification**:
      - Definir especificaciones en la clase `UserSpecification`.
      - Utilizar las especificaciones en el servicio `UserService`.
      - Probar las consultas dinámicas utilizando una herramienta como Postman.


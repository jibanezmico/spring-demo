## Capítulo 6: Implementación de Servicios en Red

### Introducción a los Servicios en Red

Los servicios en red permiten la comunicación entre aplicaciones a través de la red. Estos servicios son esenciales para la arquitectura de microservicios y aplicaciones distribuidas, donde diferentes componentes de la aplicación necesitan comunicarse entre sí.

### Implementación de un Servicio de Envío de Correos Electrónicos

La implementación de un servicio de envío de correos electrónicos se realiza utilizando Spring Boot y JavaMailSender. Este servicio permite enviar correos electrónicos desde la aplicación, lo cual es útil para notificaciones, confirmaciones de registro, restablecimiento de contraseñas, entre otros.

### Actividad Práctica

1. **Configurar las Dependencias de JavaMailSender**:
   - Añadir las dependencias necesarias en el archivo `pom.xml`:
     ```xml
     <dependency>
         <groupId>org.springframework.boot</groupId>
         <artifactId>spring-boot-starter-mail</artifactId>
     </dependency>
     ```

2. **Configurar las Propiedades del Correo Electrónico**:
   - Configurar las propiedades del correo electrónico en el archivo `application.properties`:
     ```properties
     spring.mail.host=smtp.mailtrap.io
     spring.mail.port=2525
     spring.mail.username=your-mailtrap-username
     spring.mail.password=your-mailtrap-password
     spring.mail.properties.mail.smtp.auth=true
     spring.mail.properties.mail.smtp.starttls.enable=true
     ```

3. **Crear el Servicio de Envío de Correos Electrónicos**:
   - Crear una clase `EmailService` en el paquete `service`:
     ```java
     @Service
     public class EmailService {
         private static final Logger logger = LoggerFactory.getLogger(EmailService.class);

         @Autowired
         private JavaMailSender mailSender;

         public void sendEmail(String to, String subject, String text) {
             try {
                 logger.info("Enviando correo a: {}", to);
                 SimpleMailMessage message = new SimpleMailMessage();
                 message.setTo(to);
                 message.setSubject(subject);
                 message.setText(text);
                 mailSender.send(message);
                 logger.info("Correo enviado a: {}", to);
             } catch (MailException e) {
                 logger.error("Error al enviar el correo: {}", e.getMessage());
             }
         }

         public void sendEmailWithAttachment(String to, String subject, String text, String pathToAttachment) {
             try {
                 logger.info("Enviando correo con adjunto a: {}", to);
                 MimeMessage message = mailSender.createMimeMessage();
                 MimeMessageHelper helper = new MimeMessageHelper(message, true);

                 helper.setTo(to);
                 helper.setSubject(subject);
                 helper.setText(text);

                 FileSystemResource file = new FileSystemResource(new File(pathToAttachment));
                 helper.addAttachment("Adjunto", file);

                 mailSender.send(message);
                 logger.info("Correo con adjunto enviado a: {}", to);
             } catch (MessagingException | MailException e) {
                 logger.error("Error al enviar el correo con adjunto: {}", e.getMessage());
             }
         }
     }
     ```

### Explicación del Código

- `@Service`: Indica que esta clase es un servicio de Spring.
- `JavaMailSender`: Es una interfaz proporcionada por Spring Boot para enviar correos electrónicos.
- `sendEmail(String to, String subject, String text)`: Método que envía un correo electrónico con el destinatario, asunto y texto especificados. Maneja errores utilizando un bloque `try-catch`.
- `sendEmailWithAttachment(String to, String subject, String text, String pathToAttachment)`: Método que envía un correo electrónico con un archivo adjunto. Utiliza `MimeMessageHelper` para configurar el mensaje con el archivo adjunto.

### Uso de Mailtrap para Pruebas de Correo Electrónico

Mailtrap es una herramienta que permite probar el envío de correos electrónicos sin necesidad de configurar un servidor SMTP real. Aquí se explica cómo configurarlo:

1. **Crear una Cuenta en Mailtrap**:
   - Regístrate en [Mailtrap](https://mailtrap.io/) y crea un inbox.

2. **Obtener las Credenciales SMTP**:
   - En el dashboard de Mailtrap, selecciona el inbox y copia las credenciales SMTP (host, puerto, nombre de usuario y contraseña).

3. **Configurar las Propiedades del Correo Electrónico**:
   - Configura las propiedades del correo electrónico en el archivo `application.properties` utilizando las credenciales de Mailtrap:
     ```properties
     spring.mail.host=smtp.mailtrap.io
     spring.mail.port=2525
     spring.mail.username=your-mailtrap-username
     spring.mail.password=your-mailtrap-password
     spring.mail.properties.mail.smtp.auth=true
     spring.mail.properties.mail.smtp.starttls.enable=true
     ```

### Beneficios de Usar JavaMailSender

- **Simplicidad**: JavaMailSender simplifica el envío de correos electrónicos al proporcionar una API fácil de usar.
- **Configuración Flexible**: Permite configurar diversas propiedades del correo electrónico, como el servidor SMTP, puerto, autenticación, entre otros.
- **Integración con Spring Boot**: Se integra fácilmente con aplicaciones Spring Boot, lo que facilita su configuración y uso.

### Actividad Práctica

1. **Enviar un Correo Electrónico de Prueba**:
   - Crear un controlador REST para probar el envío de correos electrónicos:
     ```java
     @RestController
     @RequestMapping("/api/email")
     public class EmailController {
         @Autowired
         private EmailService emailService;

         @PostMapping("/send")
         public ResponseEntity<String> sendEmail(@RequestParam String to, @RequestParam String subject, @RequestParam String text) {
             emailService.sendEmail(to, subject, text);
             return ResponseEntity.ok("Email sent successfully");
         }

         @PostMapping("/sendWithAttachment")
         public ResponseEntity<String> sendEmailWithAttachment(@RequestParam String to, @RequestParam String subject, @RequestParam String text, @RequestParam String pathToAttachment) {
             emailService.sendEmailWithAttachment(to, subject, text, pathToAttachment);
             return ResponseEntity.ok("Email with attachment sent successfully");
         }
     }
     ```

2. **Probar el Envío de Correos Electrónicos**:
   - Iniciar la aplicación Spring Boot.
   - Utilizar una herramienta como Postman para enviar una solicitud POST a `http://localhost:8080/api/email/send` con los parámetros `to`, `subject` y `text`.
   - Verificar que el correo electrónico se envía correctamente.

3. **Probar el Envío de Correos Electrónicos con Archivos Adjuntos**:
   - Utilizar una herramienta como Postman para enviar una solicitud POST a `http://localhost:8080/api/email/sendWithAttachment` con los parámetros `to`, `subject`, `text` y `pathToAttachment`.
   - Verificar que el correo electrónico con el archivo adjunto se envía correctamente.

### Manejo de Errores Comunes

Es importante manejar errores comunes al enviar correos electrónicos, como problemas de conexión o autenticación. Aquí hay un ejemplo de cómo manejar estos errores en el servicio de envío de correos:

```java
@Service
public class EmailService {
    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);

    @Autowired
    private JavaMailSender mailSender;

    public void sendEmail(String to, String subject, String text) {
        try {
            logger.info("Enviando correo a: {}", to);
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject(subject);
            message.setText(text);
            mailSender.send(message);
            logger.info("Correo enviado a: {}", to);
        } catch (MailAuthenticationException e) {
            logger.error("Error de autenticación: {}", e.getMessage());
        } catch (MailSendException e) {
            logger.error("Error al enviar el correo: {}", e.getMessage());
        } catch (MailException e) {
            logger.error("Error general de correo: {}", e.getMessage());
        }
    }

    public void sendEmailWithAttachment(String to, String subject, String text, String pathToAttachment) {
        try {
            logger.info("Enviando correo con adjunto a: {}", to);
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);

            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(text);

            FileSystemResource file = new FileSystemResource(new File(pathToAttachment));
            helper.addAttachment("Adjunto", file);

            mailSender.send(message);
            logger.info("Correo con adjunto enviado a: {}", to);
        } catch (MessagingException | MailException e) {
            logger.error("Error al enviar el correo con adjunto: {}", e.getMessage());
        }
    }
}
```

En este ejemplo, se manejan diferentes tipos de excepciones de correo para proporcionar mensajes de error más específicos y se utiliza un Logger para registrar eventos importantes.

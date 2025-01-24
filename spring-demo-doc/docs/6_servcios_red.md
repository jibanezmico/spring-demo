## Capítulo 6: Implementación de Servicios en Red

### Introducción a los Servicios en Red

Los servicios en red permiten la comunicación entre aplicaciones a través de la red. Son esenciales en arquitecturas distribuidas y de microservicios, facilitando la integración entre sistemas mediante protocolos como HTTP, SMTP o WebSockets. En este capítulo, se abordará la implementación de un servicio de envío de correos electrónicos utilizando Spring Boot y la interfaz JavaMailSender.

### Implementación de un Servicio de Envío de Correos Electrónicos

Para habilitar el envío de correos electrónicos en un proyecto Spring Boot, se requiere añadir la siguiente dependencia en el archivo pom.xml:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-mail</artifactId>
</dependency>
```

Configuración del Servicio de Correo Electrónico

Las propiedades de configuración se definen en el archivo application.properties:

```properties
spring.mail.host=smtp.mailtrap.io
spring.mail.port=2525
spring.mail.username=your-mailtrap-username
spring.mail.password=your-mailtrap-password
spring.mail.properties.mail.smtp.auth=true
spring.mail.properties.mail.smtp.starttls.enable=true
```

Nota: Se recomienda usar Mailtrap para pruebas, ya que permite simular el envío de correos electrónicos sin un servidor SMTP real.

Implementación del Servicio de Correo Electrónico

Se debe crear una clase de servicio en el paquete service:

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

- @Service: Indica que esta clase es un componente de servicio de Spring.
- JavaMailSender: Interfaz de Spring Boot que facilita el envío de correos electrónicos.
- sendEmail(...): Método para enviar correos electrónicos simples.
- sendEmailWithAttachment(...): Método para enviar correos con archivos adjuntos.
- Se utiliza SimpleMailMessage para mensajes sin adjuntos y MimeMessageHelper para adjuntar archivos.
- Se incorpora Logger para registrar eventos relevantes y manejar excepciones en los envíos.

**Prueba del Servicio con un Controlador REST**

Para probar el servicio, se debe crear un controlador en el paquete controller:

```java
@RestController
@RequestMapping("/api/email")
public class EmailController {
    @Autowired
    private EmailService emailService;

    @PostMapping("/send")
    public ResponseEntity<String> sendEmail(@RequestParam String to, @RequestParam String subject, @RequestParam String text) {
        emailService.sendEmail(to, subject, text);
        return ResponseEntity.ok("Correo enviado con éxito");
    }

    @PostMapping("/sendWithAttachment")
    public ResponseEntity<String> sendEmailWithAttachment(@RequestParam String to, @RequestParam String subject, 
                                                          @RequestParam String text, @RequestParam String pathToAttachment) {
        emailService.sendEmailWithAttachment(to, subject, text, pathToAttachment);
        return ResponseEntity.ok("Correo con adjunto enviado con éxito");
    }
}
```

- @RestController: Define el controlador REST para gestionar las solicitudes HTTP.
- @RequestMapping("/api/email"): Define la ruta base para las solicitudes de email.
- @PostMapping("/send"): Método para enviar correos electrónicos simples.
- @PostMapping("/sendWithAttachment"): Método para enviar correos electrónicos con adjuntos.

Pruebas con Postman

1.	Prueba de envío simple:
	- Iniciar la aplicación Spring Boot.
	- En Postman, realizar una solicitud POST a: http://localhost:8080/api/email/send
        - Parámetros:
	      - to: destinatario del correo.
	      - subject: asunto del correo.
	      - text: contenido del correo.
2.	Prueba de envío con adjunto:
    - Enviar una solicitud POST a: http://localhost:8080/api/email/sendWithAttachment
        - Parámetros:
	      - to: destinatario del correo.
	      - subject: asunto del correo.
	      - text: contenido del correo.
	      - pathToAttachment: ruta del archivo a adjuntar.

**Manejo de Errores Comunes**

Es fundamental manejar errores comunes al enviar correos electrónicos, tales como problemas de autenticación o conexión:

```java
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
```


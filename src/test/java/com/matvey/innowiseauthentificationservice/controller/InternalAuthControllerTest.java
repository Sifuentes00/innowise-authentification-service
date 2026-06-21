package com.matvey.innowiseauthentificationservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.matvey.innowiseauthentificationservice.dto.AdminRegisterRequest;
import com.matvey.innowiseauthentificationservice.dto.RegisterRequest;
import com.matvey.innowiseauthentificationservice.entity.UserCredential;
import com.matvey.innowiseauthentificationservice.enums.RoleType;
import com.matvey.innowiseauthentificationservice.repository.UserCredentialRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.LocalDate;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(classes = {
        com.matvey.innowiseauthentificationservice.InnowiseAuthentificationServiceApplication.class
})
@ActiveProfiles("test")
@Testcontainers
class InternalAuthControllerTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("innowise_authentification_service")
            .withUsername("app_user")
            .withPassword("app-password");

    @DynamicPropertySource
    static void postgresProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
    }

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private UserCredentialRepository userCredentialRepository;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;
    private UUID testUserId;

    @BeforeEach
    void setup() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule());
        testUserId = UUID.randomUUID();
    }

    @AfterEach
    void cleanup() {
        userCredentialRepository.deleteAll();
    }

    @Test
    void createCredentialsInternal_ShouldCreateUserCredential() throws Exception {
        RegisterRequest request = new RegisterRequest();
        request.setName("Test");
        request.setSurname("User");
        request.setBirthDate(LocalDate.of(1990, 1, 1));
        request.setEmail("test@example.com");
        request.setPassword("password123");

        mockMvc.perform(post("/internal/credentials/" + testUserId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());

        UserCredential user = userCredentialRepository.findByEmail("test@example.com").orElse(null);
        assertNotNull(user);
        assertEquals(testUserId, user.getUserId());
        assertEquals("test@example.com", user.getEmail());
        assertEquals(RoleType.USER, user.getRole());
    }

    @Test
    void createCredentialsInternal_ShouldReturnConflict_WhenEmailExists() throws Exception {
        RegisterRequest request = new RegisterRequest();
        request.setName("Test");
        request.setSurname("User");
        request.setBirthDate(LocalDate.of(1990, 1, 1));
        request.setEmail("test@example.com");
        request.setPassword("password123");

        mockMvc.perform(post("/internal/credentials/" + testUserId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/internal/credentials/" + UUID.randomUUID())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict());
    }

    @Test
    void createAdminCredentialsInternal_ShouldCreateAdminCredential() throws Exception {
        AdminRegisterRequest request = new AdminRegisterRequest();
        request.setName("Admin");
        request.setSurname("User");
        request.setBirthDate(LocalDate.of(1990, 1, 1));
        request.setEmail("admin@example.com");
        request.setPassword("admin123");
        request.setRole(RoleType.ADMIN);

        mockMvc.perform(post("/internal/admin-credentials/" + testUserId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());

        UserCredential user = userCredentialRepository.findByEmail("admin@example.com").orElse(null);
        assertNotNull(user);
        assertEquals(testUserId, user.getUserId());
        assertEquals("admin@example.com", user.getEmail());
        assertEquals(RoleType.ADMIN, user.getRole());
    }

    @Test
    void createAdminCredentialsInternal_ShouldReturnConflict_WhenEmailExists() throws Exception {
        AdminRegisterRequest request = new AdminRegisterRequest();
        request.setName("Admin");
        request.setSurname("User");
        request.setBirthDate(LocalDate.of(1990, 1, 1));
        request.setEmail("admin@example.com");
        request.setPassword("admin123");
        request.setRole(RoleType.ADMIN);

        mockMvc.perform(post("/internal/admin-credentials/" + testUserId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/internal/admin-credentials/" + UUID.randomUUID())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict());
    }

    @Test
    void deleteCredentialsInternal_ShouldDeleteUserCredential() throws Exception {
        RegisterRequest request = new RegisterRequest();
        request.setName("Test");
        request.setSurname("User");
        request.setBirthDate(LocalDate.of(1990, 1, 1));
        request.setEmail("delete@example.com");
        request.setPassword("password123");

        mockMvc.perform(post("/internal/credentials/" + testUserId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());

        assertNotNull(userCredentialRepository.findByEmail("delete@example.com").orElse(null));

        mockMvc.perform(delete("/internal/credentials/" + testUserId))
                .andExpect(status().isNoContent());

        assertNull(userCredentialRepository.findByEmail("delete@example.com").orElse(null));
    }

    @Test
    void deleteCredentialsInternal_ShouldReturnNoContent_WhenUserNotFound() throws Exception {
        mockMvc.perform(delete("/internal/credentials/" + UUID.randomUUID()))
                .andExpect(status().isNoContent());
    }

}

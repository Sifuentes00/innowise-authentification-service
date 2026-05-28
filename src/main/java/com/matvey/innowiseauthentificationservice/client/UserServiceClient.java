package com.matvey.innowiseauthentificationservice.client;

import com.matvey.innowiseauthentificationservice.dto.UserServiceRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class UserServiceClient {

    private final RestTemplate restTemplate;

    @Value("${user.service.url}")
    private String userServiceUrl;

    public void createUser(UUID userId, UserServiceRequest request) {
        String url = userServiceUrl + "/internal/users";

        request.setUserId(userId);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<UserServiceRequest> entity = new HttpEntity<>(request, headers);

        ResponseEntity<Void> response = restTemplate.exchange(
                url,
                HttpMethod.POST,
                entity,
                Void.class
        );

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Failed to create user in User Service. Status: " + response.getStatusCode());
        }
    }

    public void checkUserExists(UUID userId) {
        String url = userServiceUrl + "/internal/users/" + userId;

        ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("User not found in User Service");
        }
    }
}

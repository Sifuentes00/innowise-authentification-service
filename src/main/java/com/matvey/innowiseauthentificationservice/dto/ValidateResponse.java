package com.matvey.innowiseauthentificationservice.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ValidateResponse {
    private boolean valid;
    private String userId;
    private String role;
}

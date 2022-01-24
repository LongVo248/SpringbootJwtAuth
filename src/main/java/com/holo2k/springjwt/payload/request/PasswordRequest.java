package com.holo2k.springjwt.payload.request;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

public class PasswordRequest {
    @NotBlank
    @Size(min = 5, max = 40)
    private String password;

    @NotBlank
    @Size(min = 5, max = 40)
    private String newPassword;

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}

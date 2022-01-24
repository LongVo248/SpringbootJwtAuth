package com.holo2k.springjwt.security.services;

import com.holo2k.springjwt.models.User;
import org.springframework.stereotype.Service;

@Service
public interface UserService {
    Boolean checkPassword(String password, User user);

    Boolean changePassword(String password, User user);

    Boolean forgotPassword(User user);

    User checkMail(String email);
}

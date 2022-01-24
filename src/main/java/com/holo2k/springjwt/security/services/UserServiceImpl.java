package com.holo2k.springjwt.security.services;

import com.holo2k.springjwt.models.User;
import com.holo2k.springjwt.repository.UserRepository;
import com.holo2k.springjwt.util.DataUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    private UserRepository userRepository;

    private DataUtils dataUtils;

    @Override
    public Boolean checkPassword(String password, User user) {
        return null;
    }

    @Override
    public Boolean changePassword(String password, User user) {
        return null;
    }

    @Override
    public Boolean forgotPassword(User users) {
        users.setPassword(DataUtils.generateTempPwd(8));
        //clientService.forgotPassword(users, users.getPassword());
        users.setPassword(BCrypt.hashpw(users.getPassword(), BCrypt.gensalt(12)));
        userRepository.save(users);
        return true;
    }

    @Override
    public User checkMail(String email) {
        for (User users : new ArrayList<>(userRepository.findAll())) {
            if (email.equals(users.getEmail())) {
                return users;
            }
        }
        return null;
    }
}

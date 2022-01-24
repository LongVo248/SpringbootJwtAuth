package com.holo2k.springjwt.controllers;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.Valid;

import com.holo2k.springjwt.security.services.EmailService;
import com.holo2k.springjwt.payload.response.JwtResponse;
import com.holo2k.springjwt.repository.RoleRepository;
import com.holo2k.springjwt.repository.UserRepository;
import com.holo2k.springjwt.security.jwt.JwtUtils;
import com.holo2k.springjwt.security.services.UserDetailsImpl;
import com.holo2k.springjwt.security.services.UserServiceImpl;
import com.holo2k.springjwt.util.DataUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.MailException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.holo2k.springjwt.models.ERole;
import com.holo2k.springjwt.models.Role;
import com.holo2k.springjwt.models.User;
import com.holo2k.springjwt.payload.request.LoginRequest;
import com.holo2k.springjwt.payload.request.SignupRequest;
import com.holo2k.springjwt.payload.response.MessageResponse;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    private UserServiceImpl userService;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    EmailService emailService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getFirstname(),
                userDetails.getLastname(),
                userDetails.getEmail(),
                roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(), signUpRequest.getFirstname(), signUpRequest.getLastname(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);
        try {
            emailService.sendSimpleEmail(signUpRequest.getEmail(), "Hello " + signUpRequest.getUsername() + "\n" +
                    "Complete account registration!!!", "Hello " + signUpRequest.getFirstname() + " " + signUpRequest.getLastname() + "!!\n" +
                    "Welcome to Website!\n" +
                    "You can use your new account to access and use Holo2k products, apps, and services.");
        } catch (MailException mailException) {
            LOG.error("Error while sending out email..{}", mailException.getStackTrace());
            LOG.error("Error while sending out email..{}", mailException.fillInStackTrace());
            return new ResponseEntity<>("Unable to send email", HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return ResponseEntity.ok(new MessageResponse("User registered successfully! Please check your inbox !!!"));
    }

    @PostMapping("/confirmEmail")
    public ResponseEntity<?> forgetPasswordUser(@Valid @RequestBody String email) {
        email= email.substring(10,email.length()-2);
//        System.out.println(email);
        if(userRepository.existsByEmail(email)){
            for (User users : new ArrayList<>(userRepository.findAll())) {
                if (email.equals(users.getEmail())) {
                    users.setPassword(DataUtils.generateTempPwd(8));
                    String newPassword= users.getPassword();
                    users.setPassword(BCrypt.hashpw(users.getPassword(), BCrypt.gensalt(12)));
                    userRepository.save(users);
                    try {

                        emailService.sendSimpleEmail(email, "Hello \n" +
                                "Complete reset password!!!", "Hello "+ "!!\n" + "New password: "+ newPassword+"\n"+
                                "Welcome to Website!\n");
                    } catch (MailException mailException) {
                        LOG.error("Error while sending out email..{}", mailException.getStackTrace());
                        LOG.error("Error while sending out email..{}", mailException.fillInStackTrace());
                        return new ResponseEntity<>("Unable to send email", HttpStatus.INTERNAL_SERVER_ERROR);
                    }
                    return ResponseEntity.ok(new MessageResponse("User registered successfully! Please check your inbox !!!"));
                }
            }

        } else {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email no exist!"));
        }
        return ResponseEntity
                .badRequest()
                .body(new MessageResponse("Error: Email no exist!"));
    }
}

package com.holo2k.springjwt.controllers;

import com.holo2k.springjwt.models.ERole;
import com.holo2k.springjwt.models.Role;
import com.holo2k.springjwt.models.User;
import com.holo2k.springjwt.payload.request.PasswordRequest;
import com.holo2k.springjwt.payload.request.SignupRequest;
import com.holo2k.springjwt.payload.response.MessageResponse;
import com.holo2k.springjwt.repository.RoleRepository;
import com.holo2k.springjwt.repository.UserRepository;
import com.holo2k.springjwt.security.jwt.JwtUtils;
import com.holo2k.springjwt.security.services.EmailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.MailException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.io.FileNotFoundException;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    AuthenticationManager authenticationManager;

//    @Autowired
//    UserService userService;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    private static final Logger LOG = LoggerFactory.getLogger(UserController.class);

    @Autowired
    EmailService emailService;


    @GetMapping("/all")
    public String allAccess() {
        return "Public Content.";
    }

    //Board User
    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public String userAccess() {
        return "User Content.";
    }

    @GetMapping("/user/{id}")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public ResponseEntity<User> userInfo(@Valid @PathVariable("id") Long id) {
        Optional<User> userOptional = userRepository.findById(id);
        return userOptional.map(user -> new ResponseEntity<>(user, HttpStatus.OK))
                .orElseGet(() -> new ResponseEntity<>(HttpStatus.NOT_FOUND));
    }

    @PutMapping("/user/update/{id}")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')  ")
    public ResponseEntity<?> updateUser(@PathVariable("id") Long id, @RequestBody User user) {
        Optional<User> userOptional = userRepository.findById(id);
        System.out.println(id + " -" + user);
        return userOptional.map(user2 -> {
            user.setId(user2.getId());
            return new ResponseEntity<>(userRepository.save(user), HttpStatus.OK);
        }).orElseGet(() -> new ResponseEntity<>(HttpStatus.NOT_FOUND));
    }

    @PutMapping("/user/change-password/{id}")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')  ")
    public ResponseEntity<?> changePassword(@PathVariable("id") Long id, @RequestBody String password) {
        User usersChange = userRepository.findById(id).orElse(null);
        if (usersChange == null) {
            throw new UsernameNotFoundException("User not found");
        } else {
            usersChange.setPassword(BCrypt.hashpw(password, BCrypt.gensalt(12)));
            return new ResponseEntity<>(userRepository.save(usersChange), HttpStatus.OK);
        }
    }

    @PostMapping("/user/check-password/{id}")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')  ")
    public ResponseEntity<Boolean> checkPassword(@PathVariable("id") Long id, @RequestBody String password) {
        System.out.println(id +" " +password);
        User users = userRepository.findById(id).orElse(null);
        if (users == null) {
            throw new UsernameNotFoundException("User not found");
        } else {
            System.out.println(users.getPassword());
            BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
            String comparePassword = users.getPassword();
            System.out.println(passwordEncoder.matches(password, comparePassword));
            return new ResponseEntity<Boolean>(passwordEncoder.matches(password, comparePassword), HttpStatus.OK);
        }
    }


    @GetMapping("/mod")
    @PreAuthorize("hasRole('MODERATOR')")
    public String moderatorAccess() {
        return "Moderator Board.";
    }

    //Board Admin
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public List<User> adminAccess() {
        return userRepository.findAll();
    }

    @DeleteMapping("/admin/delete/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteUser(@Valid @PathVariable("id") Long id) {
        if (userRepository.existsById(id)) {
            userRepository.deleteById(id);
        }
        return ResponseEntity.ok(new MessageResponse("User deleted successfully!"));
    }

    @GetMapping("/admin/user/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MODERATOR')")
    public ResponseEntity<?> getUser(@Valid @PathVariable("id") Long id) {
        Optional<User> userOptional = userRepository.findById(id);
        return userOptional.map(user -> new ResponseEntity<>(user, HttpStatus.OK))
                .orElseGet(() -> new ResponseEntity<>(HttpStatus.NOT_FOUND));
    }

    @PutMapping("/admin/update/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MODERATOR')or  hasRole('USER') ")
    public ResponseEntity<?> updateUserAdmin(@Valid @PathVariable("id") Long id, @Valid @RequestBody User user) {
        Optional<User> userOptional = userRepository.findById(id);
        return userOptional.map(user1 -> {
            user.setId(user1.getId());
            return new ResponseEntity<>(userRepository.save(user), HttpStatus.OK);
        }).orElseGet(() -> new ResponseEntity<>(HttpStatus.NOT_FOUND));
    }

    @PostMapping("/admin/add")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> addUser(@Valid @RequestBody SignupRequest signUpRequest) {
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

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

//    @GetMapping(value = "/simple-email/{user-email}")
//    public @ResponseBody
//    ResponseEntity<String> sendSimpleEmail(@PathVariable("user-email") String email) {
//
//        try {
//            emailService.sendSimpleEmail(email, "ĐĂNG KÝ TÀI KHOẢN NGƯỜI DÙNG THÀNH CÔNG!!!", "This is a welcome email for your!!");
//        } catch (MailException mailException) {
//            LOG.error("Error while sending out email..{}", mailException.getStackTrace());
//            LOG.error("Error while sending out email..{}", mailException.fillInStackTrace());
//            return new ResponseEntity<>("Unable to send email", HttpStatus.INTERNAL_SERVER_ERROR);
//        }
//
//        return new ResponseEntity<>("Please check your inbox", HttpStatus.OK);
//    }

    @GetMapping(value = "/simple-order-email/{user-email}")
    public @ResponseBody
    ResponseEntity<String> sendEmailAttachment(@PathVariable("user-email") String email) {

        try {
            emailService.sendEmailWithAttachment(email, "Order Confirmation", "Thanks for your recent order", "classpath:purchase_order.pdf");
        } catch (MessagingException | FileNotFoundException mailException) {
            LOG.error("Error while sending out email..{}", (Object) mailException.getStackTrace());
            LOG.error("Error while sending out email..{}", mailException.fillInStackTrace());
            return new ResponseEntity<>("Unable to send email", HttpStatus.INTERNAL_SERVER_ERROR);
        }

        return new ResponseEntity<>("Please check your inbox for order confirmation", HttpStatus.OK);
    }
}

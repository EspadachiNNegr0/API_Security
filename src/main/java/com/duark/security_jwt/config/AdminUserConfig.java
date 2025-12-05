package com.duark.security_jwt.config;

import com.duark.security_jwt.entities.Role;
import com.duark.security_jwt.entities.User;
import com.duark.security_jwt.repository.RoleRepository;
import com.duark.security_jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Configuration
public class AdminUserConfig implements CommandLineRunner {

    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    @Transactional
    public void run(String... args) throws Exception {

        var roleAdminOpt = roleRepository.findByName(Role.Values.ADMIN.name());

        if (roleAdminOpt.isEmpty()) {
            throw new RuntimeException("Role ADMIN não encontrada no banco. Crie antes de rodar o sistema.");
        }

        var roleAdmin = roleAdminOpt.get();

        var userAdmin = userRepository.findByUsername("admin");

        userAdmin.ifPresentOrElse(
                user -> System.out.println("admin já existe"),
                () -> {
                    var user = new User();
                    user.setUsername("admin");
                    user.setPassword(bCryptPasswordEncoder.encode("123"));
                    user.setRoles(Set.of(roleAdmin));
                    userRepository.save(user);
                    System.out.println("Usuário admin criado com sucesso!");
                }
        );
    }
}


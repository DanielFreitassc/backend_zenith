package br.com.zenith.backend.user;



import java.util.Collections;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import at.favre.lib.crypto.bcrypt.BCrypt;

@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private IUserRepository userRepository;

    @CrossOrigin(origins = "*", allowedHeaders ="*")
    @PostMapping("/register")
    public ResponseEntity create(@RequestBody UserModel userModel){

        var cpf = this.userRepository.findByCpf(userModel.getCpf());

        if(cpf != null){
            System.out.println("Usuário já existe");

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Usúario já existe");
        }

        var passwordHashred = BCrypt.withDefaults().hashToString(12, userModel.getPassword().toCharArray());

        userModel.setPassword(passwordHashred);
        
        var userCreated = this.userRepository.save(userModel);
        return ResponseEntity.status(HttpStatus.CREATED).body(userCreated);
    }
    // Login 
    @CrossOrigin(origins = "*", allowedHeaders = "*")
    @PostMapping("/")
    public ResponseEntity<Map<String, String>> login(@RequestBody UserModel userModel) {
    var user = this.userRepository.findByCpf(userModel.getCpf());

    if (user == null || !BCrypt.verifyer().verify(userModel.getPassword().toCharArray(), user.getPassword()).verified) {
        System.out.println("Usuário ou senha inválidos");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Collections.singletonMap("error", "Usuário ou senha inválidos"));
    }

    return ResponseEntity.ok(Collections.singletonMap("message", "Login bem-sucedido"));
}


    
}


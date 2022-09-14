package ru.anna.sweater.repos;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.anna.sweater.domain.User;

public interface UserRepo extends JpaRepository<User, Long> {
    User findByUsername(String username);
}

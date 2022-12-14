package ru.anna.sweater.repos;

import org.springframework.data.repository.CrudRepository;
import ru.anna.sweater.domain.Message;

import java.util.List;

public interface MessageRepo extends CrudRepository<Message, Long> {

    List<Message> findByTag(String tag);
    
}

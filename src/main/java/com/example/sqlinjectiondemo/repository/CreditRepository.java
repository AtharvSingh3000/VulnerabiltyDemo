package com.example.sqlinjectiondemo.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.example.sqlinjectiondemo.model.Credit;

@Repository
public interface CreditRepository extends JpaRepository<Credit, Long> {

    @Query("SELECT c FROM Credit c WHERE c.cardNumber = :cardNumber")
    Credit findCreditByCardNumberSecure(@Param("cardNumber") String cardNumber);
}


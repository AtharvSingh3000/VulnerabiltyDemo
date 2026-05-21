package com.example.sqlinjectiondemo.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.sqlinjectiondemo.model.Credit;
import com.example.sqlinjectiondemo.service.CreditService;
@CrossOrigin
@RestController
@RequestMapping("/credit")
public class CreditController {

    @Autowired
    private CreditService creditService;

    // POST request to save credit card information
    @PostMapping("/add")
    public ResponseEntity<?> addCreditCard(@RequestBody Credit credit) {
        try {
            Credit savedCredit = creditService.saveCreditCard(credit);
            return ResponseEntity.ok(savedCredit); // This will return a JSON response
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error saving credit card: " + e.getMessage());
        }
    }

    // GET request to retrieve all credit card data
    @GetMapping("/all")
    public ResponseEntity<List<Credit>> getAllCreditCards() {
        try {
            List<Credit> creditCards = creditService.getAllCreditCards();
            return ResponseEntity.ok(creditCards); // Return list of all credit cards as JSON
        } catch (Exception e) {
            return ResponseEntity.status(500).body(null);
        }
    }




    @GetMapping("/newall")
    public ResponseEntity<List<Credit>> getAllCreditCardsnew() {
        try {
            List<Credit> creditCards = creditService.getAllCreditCardsnew();
            return ResponseEntity.ok(creditCards); // Return list of all credit cards as JSON
        } catch (Exception e) {
            return ResponseEntity.status(500).body(null);
        }
    }


    // GET request to retrieve credit card by ID
    @GetMapping("/{id}")
    public ResponseEntity<Credit> getCreditCardById(@PathVariable Long id) {
        try {
            Credit credit = creditService.getCreditCardById(id);
            if (credit != null) {
                return ResponseEntity.ok(credit); // Return a single credit card as JSON
            } else {
                return ResponseEntity.status(404).body(null); // Not found
            }
        } catch (Exception e) {
            return ResponseEntity.status(500).body(null);
        }
    }
}

package com.example.sqlinjectiondemo.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.sqlinjectiondemo.controller.EncryptionUtil;
import com.example.sqlinjectiondemo.model.Credit;
import com.example.sqlinjectiondemo.repository.CreditRepository;

@Service
public class CreditService {

    @Autowired
    private CreditRepository creditRepository;

    // Method to save credit card information (Encrypt credit card number)
    public Credit saveCreditCard(Credit credit) {
        try {
            // Encrypt credit card number
            String encryptedCardNumber = EncryptionUtil.encrypt(credit.getCardNumber());
            credit.setCardNumber(encryptedCardNumber);
            return creditRepository.save(credit);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting credit card number", e);
        }
    }

    // Method to retrieve all credit card information (Decrypt credit card number)
    public List<Credit> getAllCreditCards() {
        List<Credit> creditCards = creditRepository.findAll();
        for (Credit credit : creditCards) {
            try {
                // Decrypt the credit card number
                String decryptedCardNumber = EncryptionUtil.decrypt(credit.getCardNumber());
                credit.setCardNumber(decryptedCardNumber);
            } catch (Exception e) {
                throw new RuntimeException("Error decrypting credit card number", e);
            }
        }
        return creditCards;
    }

    // Method to retrieve a credit card by ID (Decrypt credit card number)
    public Credit getCreditCardById(Long id) {
        Credit credit = creditRepository.findById(id).orElse(null);
        if (credit != null) {
            try {
                // Decrypt the credit card number
                String decryptedCardNumber = EncryptionUtil.decrypt(credit.getCardNumber());
                credit.setCardNumber(decryptedCardNumber);
            } catch (Exception e) {
                throw new RuntimeException("Error decrypting credit card number", e);
            }
        }
        return credit;
    }

    public List<Credit> getAllCreditCardsnew() {
        // TODO Auto-generated method stub
        List<Credit> creditCards = creditRepository.findAll();
      
        return creditCards;
    }
}

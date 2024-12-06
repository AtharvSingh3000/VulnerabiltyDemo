package com.example.sqlinjectiondemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.servlet.http.HttpSession;
import org.springframework.transaction.annotation.Transactional;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.List;

@Controller
@RequestMapping("/login")
public class LoginController {

    @Autowired
    private UserRepository userRepository;

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * Handles the login POST request.
     * Vulnerable to SQL Injection if UserRepository uses unsafe queries.
     */
    @PostMapping
public String login(@RequestParam String username, 
                    @RequestParam String password, 
                    @RequestParam(required = false, defaultValue = "insecure") String mode, 
                    HttpSession session) {
    if ("secure".equalsIgnoreCase(mode)) {
        // Secure login
        return secureLogin(username, password, session);
    } else {
        // Insecure login
        User user = userRepository.findUserByUsernameAndPassword(username, password);

        if (user != null) {
            // Check if SQL injection pattern was used
            if (username.contains("'") || username.contains("--") || username.toLowerCase().contains("or")) {
                // Redirect to a special endpoint for showing all users
                return "redirect:/login/sqlInjectionSuccess";
            }

            // Set session attribute for logged-in user
            session.setAttribute("username", username);
            return "redirect:/success.html"; // Redirect to success page
        } else {
            return "redirect:/login.html?error=Invalid%20credentials"; // Redirect with error message
        }
    }
}

    @PostMapping("/secure")
public String secureLogin(@RequestParam String username, @RequestParam String password, HttpSession session) {
    // Use the secure method for authentication
    User user = userRepository.findUserByUsernameAndPasswordSecure(username, password);

    if (user != null) {
        // Set session attribute for logged-in user
        session.setAttribute("username", username);
        return "redirect:/success.html"; // Redirect to success page
    } else {
        return "redirect:/login.html?error=Invalid%20credentials"; // Redirect with error message
    }
}


    /**
     * Displays all users only when SQL Injection is performed.
     */
    @GetMapping("/sqlInjectionSuccess")
    @ResponseBody
    public String displayAllUsersForSQLInjection() {
        List<User> users = userRepository.findAll(); // Fetch all users
        StringBuilder response = new StringBuilder("<html><body>");
        response.append("<h2>All Users (SQL Injection Successful)</h2>");
        response.append("<table border='1'><tr><th>Username</th><th>Password</th></tr>");

        // Add each user's data to the response
        for (User u : users) {
            response.append("<tr><td>").append(u.getUsername()).append("</td>")
                    .append("<td>").append(u.getPassword()).append("</td></tr>");
        }

        response.append("</table></body></html>");
        return response.toString(); // Return the HTML response displaying all users
    }
 

    @PostMapping("/change-password")
    @ResponseBody
    @Transactional
    public String changePassword(@RequestParam String username, @RequestParam String newPassword) {
        try {
            // Vulnerable SQL query (DO NOT USE IN PRODUCTION)
            String query = "UPDATE User SET password = '" + newPassword + "' WHERE username = '" + username + "'";
            int rowsUpdated = entityManager.createNativeQuery(query).executeUpdate();
            return rowsUpdated > 0
                    ? "Password updated successfully for user: " + username
                    : "Error: User not found.";
        } catch (Exception e) {
            return "Error updating password: " + e.getMessage();
        }
    }
    
    @PostMapping("/secure-change-password")
@ResponseBody
@Transactional
public String secureChangePassword(@RequestParam String username, @RequestParam String newPassword) {
    try {
        // Secure query using parameterized SQL
        String query = "UPDATE User SET password = :newPassword WHERE username = :username";
        int rowsUpdated = entityManager.createNativeQuery(query)
                .setParameter("username", username)
                .setParameter("newPassword", newPassword)
                .executeUpdate();
        return rowsUpdated > 0
                ? "Password updated successfully for user: " + username
                : "Error: User not found.";
    } catch (Exception e) {
        return "Error updating password: " + e.getMessage();
    }
}

    /**
     * Handles the logout GET request.
     */
    @GetMapping("/logout")
    public String logout(HttpSession session) {
        // Invalidate the session and redirect to login page
        session.invalidate();
        return "redirect:/login.html"; // Redirect to login page
    }

    /**
     * Endpoint to display a message without sanitization.
     * Demonstrates a potential XSS vulnerability.
     */
  



   // Vulnerable endpoint, no escaping of user input (for XSS)
   @GetMapping("/message")
   @ResponseBody
   public String getMessage(@RequestParam String msg) {
       // Return the message directly to the browser without escaping (Vulnerable)
       return "<html><body><h2>Message:</h2><p>" + msg + "</p></body></html>";
   }

   // Safe endpoint, escaping user input to prevent XSS
   @GetMapping("/safe-message")
   @ResponseBody
   public String getSafeMessage(@RequestParam String msg) {
       // Escape the user input to prevent XSS attack
       String safeMsg = HtmlUtils.htmlEscape(msg);
       return "<html><body><h2>Safe Message:</h2><p>" + safeMsg + "</p></body></html>";
   }



    @PostMapping("/execute")
    public ResponseEntity<String> executeCommand(@RequestParam String command) {
        try {
            // Explicitly invoke the shell
            String[] cmd = {"/bin/sh", "-c", command}; // Use "-c" to execute the command string
            Process process = Runtime.getRuntime().exec(cmd);
    
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
    
            // Read the process output
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            process.waitFor();
    
            // Return the command output
            return ResponseEntity.ok("Command executed successfully:\n" + output.toString());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error executing command: " + e.getMessage());
        }
    }
    @PostMapping("/secure-execute")
    public ResponseEntity<String> secureExecuteCommand(@RequestParam String command) {
        try {
            // Define allowed commands
            List<String> allowedCommands = List.of("ls", "whoami", "pwd");
    
            // Check if the command is in the list of allowed commands
            if (!allowedCommands.contains(command)) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("Error: Command not allowed!");
            }
    
            // Explicitly invoke the shell and pass the command
            String[] cmd = {"/bin/sh", "-c", command};
            Process process = Runtime.getRuntime().exec(cmd);
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
    
            // Read the process output
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            process.waitFor();
    
            // Return the command output
            return ResponseEntity.ok("Command executed successfully:\n" + output.toString());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error executing command: " + e.getMessage());
        }
    }

    @GetMapping("/admin")
    @ResponseBody
    public String adminPage(HttpSession session) {
        // No proper checks for admin role
        String loggedInUser = (String) session.getAttribute("username");
        if (loggedInUser != null) {
            return "<html><body><h1>Welcome to Admin Page, " + loggedInUser + "!</h1>"
                    + "<p>This page should be restricted but is accessible without proper checks.</p>"
                    + "</body></html>";
        } else {
            return "<html><body><h1>Access Denied!</h1>"
                    + "<p>You are not logged in, but no proper checks exist here.</p>"
                    + "</body></html>";
        }
    }
    
    /**
     * Secure version of the admin page with proper checks.
     */
    @GetMapping("/secure-admin")
    @ResponseBody
    public String secureAdminPage(HttpSession session) {
        // Proper check for admin role
        String loggedInUser = (String) session.getAttribute("username");
        if ("admin".equalsIgnoreCase(loggedInUser)) {
            return "<html><body><h1>Welcome to Secure Admin Page, " + loggedInUser + "!</h1>"
                    + "<p>This page is restricted to admins only.</p>"
                    + "</body></html>";
        } else if (loggedInUser != null) {
            return "<html><body><h1>Access Denied!</h1>"
                    + "<p>You are logged in as " + loggedInUser + " but not authorized to access this page.</p>"
                    + "</body></html>";
        } else {
            return "<html><body><h1>Access Denied!</h1>"
                    + "<p>Please log in as admin to access this page.</p>"
                    + "</body></html>";
        }
    }  


}
